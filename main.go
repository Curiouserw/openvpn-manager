//go:generate statik -src=$PWD/public
package main

import (
	_ "curiouser.com/openvpn-manager/statik"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rakyll/statik/fs"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type ClientConInfo struct {
	Username                string `json:"username"`
	IP                      string `json:"ip"`
	Port                    string `json:"port"`
	VIP                     string `json:"v_ip"`
	ReceivedBytes           string `json:"received_bytes"`
	SentBytes               string `json:"sent_bytes"`
	ConnectedSinceTimestamp string `json:"connected_since_timestamp"`
	ClientId                string `json:"client_id"`
	PeerId                  string `json:"peer_id"`
}

type OnlineClients struct {
	Onlineclients []ClientConInfo `json:"onlineclient"`
}

type User struct {
	Username string `json:"username"`
}

type Users struct {
	Users []User `json:"users"`
}

var (
	ip_reg       = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	port_reg     = regexp.MustCompile(`\((.*?)\)`)
	omhost       string
	omport       string
	ompasswd     string
	omadminpassw string
	omvpnpswfile string

	router          *gin.Engine
	authorizedRoute *gin.RouterGroup
)

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

	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}

	//根路由设置首页跳转到'/public'加载'index.html'
	router.GET("/", func(context *gin.Context) {
		context.Request.URL.Path = "/public"
		router.HandleContext(context)
	})

	authorizedRoute.StaticFS("/public", statikFS)
	//authorizedRoute.StaticFS("/public",http.Dir("./public"))
	authorizedRoute.StaticFile("/favicon.ico", "./public/favicon.ico")

	authorizedRoute.GET("/getOnlineClients", func(context *gin.Context) {

		res := sendDataToSocket(omhost+":"+omport, "status")
		origin_status := strings.Split(string(res[0:len(res)]), "\r\n")
		var client *ClientConInfo
		var oc OnlineClients
		for _, s := range origin_status {
			if find := strings.HasPrefix(s, "CLIENT_LIST"); find {
				var b = strings.Split(s, ",")
				client = &ClientConInfo{
					Username: b[1],
					//IP:                        ip_reg.FindAllString(b[2], -1)[0],
					//Port:                      port_reg.FindAllString(b[2], -1)[0],
					IP:                      strings.Split(b[2], ":")[0],
					Port:                    strings.Split(b[2], ":")[1],
					VIP:                     b[3],
					ReceivedBytes:           b[5],
					SentBytes:               b[6],
					ConnectedSinceTimestamp: b[8],
					ClientId:                b[10],
					PeerId:                  b[11],
				}
				oc.Onlineclients = append(oc.Onlineclients, *client)
			}
		}

		jsons, _ := json.Marshal(oc)
		context.JSON(http.StatusOK, string(jsons))
	})
	authorizedRoute.POST("/kickOutClientByCN", func(context *gin.Context) {
		username := context.PostForm("username")
		_ = sendDataToSocket(omhost+":"+omport, "kill "+username)
	})
	authorizedRoute.GET("/getAllUsers", func(context *gin.Context) {
		filedata, err := ioutil.ReadFile(omvpnpswfile)
		if err != nil {
			fmt.Println("读取文件失败！")
		}
		r2 := csv.NewReader(strings.NewReader(string(filedata)))
		ss, _ := r2.ReadAll()
		sz := len(ss)
		var euser *User
		var eusers Users
		// 循环取数据
		for i := 0; i < sz; i++ {
			euser = &User{Username: strings.Split(ss[i][0], " ")[0]}
			eusers.Users = append(eusers.Users, *euser)
		}
		json, _ := json.Marshal(eusers)
		context.JSON(http.StatusOK, string(json))
	})
	fmt.Println("OpenVPN Manager监听端口9090，访问地址：http://127.0.0.1:9090")
	router.Run(":9090")

}

func sendDataToSocket(conf string, msg string) (resData []byte) {

	conn, err := net.Dial("tcp", conf)

	if err != nil {
		log.Fatalf("连接失败")
	}
	buf1 := make([]byte, 2048)
	buf := make([]byte, 2048)
	conn.Read(buf)
	writeMsg := msg + "\n"
	_, err = conn.Write([]byte(writeMsg))
	if err != nil {
		fmt.Printf("发送数据失败, %s\n", err)
	}
	_, err = conn.Read(buf1)
	if err != nil {
		fmt.Printf("读取数据失败, %s\n", err)
	}
	conn.Close()
	return buf1

}
