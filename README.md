# OpenVPN Manager(重构)

# 一、简介

OpenVPN Manager，一个简单的OpenVPN Web管理工具。可通过OpenVPN的管理端口获取数据，然后在Web页面上展示或者操作。

OpenVPN的管理端口详细介绍文章，请参考：https://openvpn.net/community-resources/management-interface/

# 二、功能

- 显示当前登录的客户端信息
- 可下线用户
- 界面进行简单的用户名密码认证

![](assets/openvpn-manager-1.png)

> 表格排序规则是根据用户角色进行分组，组内根据发送数据大小进行倒序排列。

# 三、安装部署

## 1、部署所需条件：
- **OpenVPN 服务端需要开起管理端口**

  - 在OpenVPN服务端配置文件中追加`management 127.0.0.1 123456`，然后重启OpenVPN即可。
- **需要读取 openvpn 的密码文本文件**
  - 需要获取到所有用户的用户名与中文名（相关内容参考：[openvpn用户名密码认证方式实现](https://gitbooks.curiouser.top/origin/openvpn-server.html?h=openvpn#2%E3%80%81%E8%AE%BE%E7%BD%AE%E7%94%A8%E6%88%B7%E5%90%8D%E5%AF%86%E7%A0%81%E5%8A%A0%E8%AF%81%E4%B9%A6%E7%9A%84%E6%96%B9%E5%BC%8F%E7%99%BB%E5%BD%95%E8%AE%A4%E8%AF%81)）
  - 密码文本文件的格式为：`用户中文 用户名 密码` （以空格分割，一行一个）
  
- **openvpn 2.4.x 以后的版本**

- (可选)在代码根目录创建 config.json,其中可配置常见客户端登录地的网络公网IP地址。以显示非常见登录地的客户端。如果openvpn 服务端开起了根据用户角色分配不同网段的 Virtual IP情况下，可配置 Virtual IP地址网段与角色的映射关系，可以显示出用户的角色信息。
  ```json
  {
    "officeSiteIP": "111.112.113.114",
    "ipRoleMap": {
      "10.1.2.0/24": "业务人员",
      "10.1.3.0/24": "未启用",
      "10.1.4.0/24": "开发人员",
      "10.1.5.0/24": "测试人员",
      "10.1.6.0/24": "运维人员"
    }
  }
  ```

## 2、源码编译部署

```bash
git clone 
cd openvpn-manager
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -o target/openvpn-manager main.go 
nohup ./openvpn-manager -host "openvpn服务端主机IP地址" -port "openvpn管理端口" -passwd "openvpn管理端口的密码" -admin-passwd "OpenVPN Manager管理员admin的密码" -psw-file /etc/openvpn/server/psw-file >> /var/log/openvpn-manager.log 2>&1 &
```

## 3、docker方式部署

```bash
docker pull curiouser/openvpn-manager:v1
docker run \
-v $PWD/psw-file:/etc/openvpn/server/psw-file:ro \
-p 30080:9090 \
-it \
curiouser/openvpn-manager:v1 \
-host 172.16.1.2 -port 32099 -passwd "openvpn管理端口的密码" -admin-passwd 12356789 -psw-file /etc/openvpn/server/psw-file
```
