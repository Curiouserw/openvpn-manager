package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type UserInfo struct {
	Username        string `json:"username"`
	ChineseUsername string `json:"chinese_username"` // 新增字段保存中文名
	IP              string `json:"ip"`
	Port            string `json:"port"`
	VIP             string `json:"v_ip"`
	Role            string `json:"role"`
	ReceivedBytes   int    `json:"received_bytes"`
	SentBytes       int    `json:"sent_bytes"`
	LoginTime       string `json:"login_time"`
	ConnectedTime   string `json:"connected_time"`
	ClientId        string `json:"client_id"`
	PeerId          string `json:"peer_id"`
	Status          string `json:"status"`
}

type UsersList []UserInfo

type AppConfig struct {
	OfficeSiteIP string            `json:"officeSiteIP"`
	IPRoleMap    map[string]string `json:"ipRoleMap"`
}

var (
	omhost       string
	omport       string
	ompasswd     string
	omadminpassw string
	omvpnpswfile string

	once               sync.Once
	router             *gin.Engine
	authorizedRoute    *gin.RouterGroup
	allUsers           []UserInfo
	usernameChineseMap = make(map[string]string)
	appconfig          = AppConfig{}
)

//go:embed statics/*
var f embed.FS

func init() {

	flag.StringVar(&omhost, "host", "", "OpenVPN服务端地址")
	flag.StringVar(&omport, "port", "", "OpenVPN服务端管理端口，默认为空")
	flag.StringVar(&ompasswd, "passwd", "", "OpenVPN服务端管理端口密码")
	flag.StringVar(&omadminpassw, "admin-passwd", "", "OpenVPN Manager管理员admin的密码")
	flag.StringVar(&omvpnpswfile, "psw-file", "", "OpenVPN用于验证用户的密码文件")
	flag.Parse()

	gin.SetMode(gin.ReleaseMode)
	gin.ForceConsoleColor()
	router = gin.Default()

	authorizedRoute = router.Group("/", gin.BasicAuth(gin.Accounts{
		"admin": omadminpassw,
	}))
}

// 函数用于将时间戳转换为连接时间的格式
func convertTsToTime(timestampStr string) string {
	timestampInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		// 处理错误
		return "无效的时间戳"
	}
	connectedTime := time.Unix(timestampInt, 0)
	currentTime := time.Now()

	duration := currentTime.Sub(connectedTime)

	if duration.Hours() < 1 {
		if duration.Minutes() < 1 {
			return "不足1分钟"
		}
		return fmt.Sprintf("%.0f分钟", duration.Minutes())
	}

	if duration.Hours() < 24 {
		// 修改这里，将小时和分钟分别拆分成整数部分和小数部分
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		return fmt.Sprintf("%d小时%d分钟", hours, minutes)
	}

	// 修改这里，将小时和分钟分别拆分成整数部分和小数部分
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	return fmt.Sprintf("%d时%d分", hours, minutes)
}

// 函数用于将字符串类型的时间戳转换为连接时间的格式
func formatConnectedTime(timestampStr string) string {
	timestampInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		// 处理错误
		return "无效的时间戳"
	}

	return time.Unix(timestampInt, 0).Format("2006-01-02 15:04:05")
}

// 函数用于将字节数转换为更大单位（KB、MB、GB）
func formatBytes(bytes int) string {
	// 转换单位
	kb := float64(bytes) / 1024
	mb := kb / 1024
	gb := mb / 1024

	switch {
	case gb >= 1:
		return fmt.Sprintf("%.2f GB", gb)
	case mb >= 1:
		return fmt.Sprintf("%.2f MB", mb)
	case kb >= 1:
		return fmt.Sprintf("%.2f KB", kb)
	default:
		return fmt.Sprintf("%d Bytes", bytes)
	}
}

// serveStaticFile 用于处理静态文件请求
func serveStaticFile(filepath, contentType string) func(c *gin.Context) {
	return func(c *gin.Context) {
		content, err := f.ReadFile(filepath)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error reading file")
			return
		}
		c.Data(http.StatusOK, contentType, content)
	}
}

// isJavaScriptRequest 判断是否为JavaScript请求
func isJavaScriptRequest(req *http.Request) bool {
	return req.Header.Get("Accept") == "application/javascript" || req.Header.Get("Content-Type") == "application/javascript"
}

func main() {
	if omhost == "" && omport == "" && omadminpassw == "" && omvpnpswfile == "" {
		fmt.Println("没有设置OpenVPN服务端的主机IP地址、管理端口及管理员密码，请在启动命令后添加'-host'，'-port'，'-admin-passwd'，'-omvpnpswfile'参数设置")
		os.Exit(0)
	} else if omhost == "" {
		fmt.Println("OpenVPN服务端主机IP地址没有设置，无法启动。请在启动命令后添加'-host'参数设置IP地址")
		os.Exit(0)
	} else if omport == "" {
		fmt.Println("OpenVPN管理端口没有设置，无法启动。请在启动命令后添加'-port'参数设置管理端口号")
		os.Exit(0)
	} else if omadminpassw == "" {
		fmt.Println("OpenVPN Manager管理员admin用户的密码没有设置，无法启动。请在启动命令后添加'-admin-passwd'参数进行设置")
		os.Exit(0)
	} else if omvpnpswfile == "" {
		fmt.Println("OpenVPN用于验证用户的密码文件路径没有设置，无法启动。请在启动命令后添加'-omvpnpswfile'参数进行设置")
		os.Exit(0)
	}
	configFileContent, err := os.ReadFile("config.json")
	if err != nil {
		fmt.Println("当前目录下未发现配置文件config.json，本次启动将使用默认值。可创建配置，格式为json，配置项和内容可为：")
		fmt.Println("   {\"officeSiteIP\": \"客户端常见登录地址所在网络的公网IP 地址\", \"ipRoleMap\": { \"10.0.1.0/24\" : \"开发人员\", \"10.0.2.0/24\" : \"测试人员\", \"10.0.3.0/24\" : \"业务人员\" }")
	} else {
		err = json.Unmarshal(configFileContent, &appconfig)
		if err != nil {
			fmt.Println("当前目录下的config.json无法解析，本次启动不使用其中设置。格式为json，请进行检查。样例如下：")
			fmt.Println("   {\"officeSiteIP\": \"客户端常见登录地址所在网络的公网IP 地址\", \"ipRoleMap\": { \"10.0.1.0/24\" : \"开发人员\", \"10.0.2.0/24\" : \"测试人员\", \"10.0.3.0/24\" : \"业务人员\" }")
		} else {
			if appconfig.OfficeSiteIP == "" && appconfig.IPRoleMap == nil {
				println("当前目录下config.json没有配置officeSiteIP(用于突出显示非常见客户端登录地址所在网络公网IP地址)和IPRoleMap(在根据Virtual IP网段划分用户角色时，该参数可配置为IP地址网段与角色的映射) 。本次启动将使用默认值。格式为json，请进行检查。样例如下:")
				println("   {\"officeSiteIP\": \"客户端常见登录地址所在网络的公网IP 地址\", \"ipRoleMap\": { \"10.0.1.0/24\" : \"开发人员\", \"10.0.2.0/24\" : \"测试人员\", \"10.0.3.0/24\" : \"业务人员\" }")
			}
			if appconfig.OfficeSiteIP == "" {
				println("当前目录下config.json没有配置officeSiteIP(用于突出显示非常见客户端登录地址所在网络公网IP地址) 。本次启动将使用默认值。格式为json，请进行检查。样例如下:")
				println("   {\"officeSiteIP\": \"客户端常见登录地址所在网络的公网IP 地址\"}")
			}
			if appconfig.IPRoleMap == nil {
				println("\"当前目录下config.json没有配置IPRoleMap(在根据Virtual IP网段划分用户角色时，该参数可配置为IP地址网段与角色的映射)，本次启动将使用默认值。格式为json，请进行检查。样例如下：")
				println("   {\"ipRoleMap\": { \"10.0.1.0/24\" : \"开发人员\", \"10.0.2.0/24\" : \"测试人员\", \"10.0.3.0/24\" : \"业务人员\" }")
			}
		}
	}

	getAllUsers()

	router.Use(func(c *gin.Context) {
		cacheControl := "public, max-age=3600"
		if isJavaScriptRequest(c.Request) {
			cacheControl = "public, max-age=86400"
		}
		c.Header("Cache-Control", cacheControl)
		c.Next()
	})

	authorizedRoute.GET("/", func(context *gin.Context) {
		userInfos := processUserInfos(allUsers, getOnlineUsers())
		htmlContent, err := f.ReadFile("statics/index.html")
		if err != nil {
			context.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		// 构造传入template的数据变量。
		templateVariables := struct {
			Users      UsersList
			SpecificIP string
		}{
			Users:      userInfos,
			SpecificIP: appconfig.OfficeSiteIP,
		}
		// 创建模板对象并解析模板，同时也映射了一个本地函数formatBytes，以便html模板中可以调用
		tmpl, err := template.New("index").Funcs(template.FuncMap{"formatBytes": formatBytes}).Parse(string(htmlContent))
		if err != nil {
			context.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		context.Header("Content-Type", "text/html")
		// 渲染模板，并将模板变量传递给模板。以便html模板中可以引用
		err = tmpl.Execute(context.Writer, templateVariables)
		if err != nil {
			context.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
	})

	authorizedRoute.GET("/js/:filename", func(c *gin.Context) {
		filename := c.Param("filename")
		serveStaticFile("statics/js/"+filename, "application/javascript")(c)
	})
	authorizedRoute.POST("/kickOutClientByCN", func(context *gin.Context) {
		var requestData map[string]interface{}
		if err := context.ShouldBindJSON(&requestData); err != nil {
			context.JSON(400, gin.H{"error": err.Error()})
			return
		}
		username, exists := requestData["username"].(string)
		if !exists {
			context.JSON(400, gin.H{"error": "Missing or invalid 'username' field"})
			return
		} else {
			_ = sendDataToSocket(omhost+":"+omport, "kill "+username)
			context.JSON(http.StatusOK, "{\"status\":\"success\"}")
		}
	})
	fmt.Println("OpenVPN Manager监听端口9091，访问地址：http://127.0.0.1:9091")
	err = router.Run(":9091")
	if err != nil {
		return
	}
}

func getOnlineUsers() []UserInfo {
	res := sendDataToSocket(omhost+":"+omport, "status")
	originStatus := strings.Split(res, "\r\n")
	var users []UserInfo
	for _, s := range originStatus {
		if find := strings.HasPrefix(s, "CLIENT_LIST"); find {
			var b = strings.Split(s, ",")
			sendby, _ := strconv.Atoi(b[6])
			userip := strings.Split(b[2], ":")[0]
			role := getRoleFromIP(b[3])
			connectedTime := convertTsToTime(b[8])
			loginTime := formatConnectedTime(b[8])
			receivedbytes, _ := strconv.Atoi(b[5])
			userInfo := UserInfo{
				Username:      b[1],
				IP:            userip,
				Port:          strings.Split(b[2], ":")[1],
				VIP:           b[3],
				Role:          role,
				ReceivedBytes: receivedbytes,
				SentBytes:     sendby,
				LoginTime:     loginTime,
				ConnectedTime: connectedTime,
				ClientId:      b[10],
				PeerId:        b[11],
			}
			users = append(users, userInfo)
		}
	}
	return users
}

// 根据 VIP 地址判断角色
func getRoleFromIP(ip string) string {
	if appconfig.IPRoleMap == nil {
		return "未设置角色"
	} else {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return "错误IP"
		}
		for ipRange, role := range appconfig.IPRoleMap {
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				continue
			}
			if ipNet.Contains(parsedIP) {
				return role
			}
		}
		return "未知角色"
	}
}

// 从密码文本中获取所有的用户名
func getAllUsers() []UserInfo {
	once.Do(func() {
		fileContent, err := os.ReadFile(omvpnpswfile)
		if err != nil {
			fmt.Println("Error reading file:", err)
			panic(err)
		}
		lines := strings.Split(string(fileContent), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				userInfo := UserInfo{
					Username: strings.TrimSpace(parts[1]),
				}
				username := strings.TrimSpace(parts[1])
				chineseName := strings.TrimSpace(parts[0])
				usernameChineseMap[username] = chineseName
				allUsers = append(allUsers, userInfo)
			}
		}
	})
	return allUsers
}

// 发送 socket 数据
func sendDataToSocket(conf string, msg string) (resData string) {
	conn, err := net.Dial("tcp", conf)
	if err != nil {
		log.Fatalf("连接失败")
	}

	buf1 := make([]byte, 8096)
	buf := make([]byte, 8096)

	_, err = conn.Read(buf)
	if err != nil {
		fmt.Printf("连接失败！, %s\n", err)
	}
	writeMsg := msg + "\n"

	_, err = conn.Write([]byte(ompasswd + "\n"))
	if err != nil {
		fmt.Printf("管理端口认证失败, %s\n", err)
	}
	_, err = conn.Write([]byte(writeMsg))
	if err != nil {
		fmt.Printf("发送数据失败, %s\n", err)
	}
	time.Sleep(1 * time.Second)
	nlen, err := conn.Read(buf1)
	if err != nil {
		fmt.Printf("读取数据失败, %s\n", err)
		return
	}
	err = conn.Close()
	if err != nil {
		fmt.Printf("连接关闭失败！, %s\n", err)
	}

	return string(buf1[:nlen])
}

func SortBySentBytesAndRole(u UsersList) {
	sort.Slice(u, func(i, j int) bool {
		// 获取中文名的拼音，仅赋值给ChineseUsername字段
		u[i].ChineseUsername, u[j].ChineseUsername = getChineseName(u[i].Username), getChineseName(u[j].Username)
		// 如果 Role 相同，则按照 SentBytes 排序
		if u[i].Role == u[j].Role {
			// 空值或零值的 SentBytes 不参与排序，直接往后放
			if u[i].SentBytes == 0 || u[j].SentBytes == 0 {
				return u[j].SentBytes == 0 // 零值的放在后面
			}
			return u[i].SentBytes > u[j].SentBytes
		}
		// 如果 Role 不同，则按照 Role 的字典序排序
		return u[i].Role > u[j].Role
	})
}

func getChineseName(username string) string {
	if chineseName, ok := usernameChineseMap[username]; ok {
		return chineseName
	}
	return username
}

func processUserInfos(localUserInfos, socketData []UserInfo) []UserInfo {
	var updatedUserInfos UsersList
	for _, socketUser := range socketData {
		// 检查用户名是否存在于 localUserInfos 中
		localUserInfo := findUserInfoByUsername(localUserInfos, socketUser.Username)
		if localUserInfo != nil {
			// 使用 socketUser 的附加数据更新 localUserInfo
			localUserInfo.IP = socketUser.IP
			localUserInfo.Port = socketUser.Port
			localUserInfo.VIP = socketUser.VIP
			localUserInfo.Role = socketUser.Role
			localUserInfo.ReceivedBytes = socketUser.ReceivedBytes
			localUserInfo.SentBytes = socketUser.SentBytes
			localUserInfo.LoginTime = socketUser.LoginTime
			localUserInfo.ConnectedTime = socketUser.ConnectedTime
			localUserInfo.Status = "online"
			updatedUserInfos = append(updatedUserInfos, *localUserInfo)
		} else {
			// 如果在 localUserInfos 中未找到，作为未知用户添加
			unknownUser := UserInfo{
				Username: socketUser.Username,
				Status:   "unknown",
			}
			updatedUserInfos = append(updatedUserInfos, unknownUser)
		}
	}
	// 处理离线用户
	for _, localUserInfo := range localUserInfos {
		if !containsUsername(updatedUserInfos, localUserInfo.Username) {
			localUserInfo.Status = "offline"
			updatedUserInfos = append(updatedUserInfos, localUserInfo)
		}
	}
	SortBySentBytesAndRole(updatedUserInfos)
	return updatedUserInfos
}

func findUserInfoByUsername(userInfos []UserInfo, username string) *UserInfo {
	for i := range userInfos {
		if userInfos[i].Username == username {
			return &userInfos[i]
		}
	}
	return nil
}

// 检查用户名是否存在于用户信息切片中
func containsUsername(userInfos []UserInfo, username string) bool {
	for _, userInfo := range userInfos {
		if userInfo.Username == username {
			return true
		}
	}
	return false
}
