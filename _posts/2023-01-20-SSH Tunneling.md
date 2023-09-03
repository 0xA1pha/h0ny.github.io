---
layout: post
title: SSH Tunneling
category: [Linux]
tags: [linux, ssh, tunnel]
---

## Overiew

SSH 隧道（也称为 SSH 端口转发）是通过在现有 SSH 会话中传输附加数据流的方式实现的，能将其他 TCP/IP 端口的网络数据通过 SSH 连接进行转发，并且自动提供了相应的加密及解密服务。由于数据流量被定向到加密的 SSH 连接内流动，因此在传输过程中不会被窃听或拦截。

SSH 隧道一般通过本地端口转发、远程端口转发、动态端口转发或创建 TUN/TAP 隧道来实现。

以下是 SSH 命令常用的一些参数选项以及简要描述：

| 选项 | 描述                                              |
| ---- | ------------------------------------------------- |
| -L   | 开启本地端口转发，并指定地址和端口                |
| -R   | 开启远程端口转发，并指定地址和端口                |
| -D   | 开启动态端口转发（SOCKS Proxy），并指定地址和端口 |
| -g   | 允许远程主机连接到本地转发端口                    |
| -C   | 压缩数据                                          |
| -N   | 不登录远程 Shell，仅进行端口转发                  |
| -f   | 将 SSH 连接放在后台运行                           |
| -i   | 指定 SSH 私钥                                     |
| -v   | 详细模式                                          |

> 注：
>
> 1. 只有 root 用户可以转发特权端口（端口号小于 1024 的端口）。
> 2. 本地、远程、动态端口转发，可以在一条命令中同时进行配置。

## Local Forwarding

将访问本机指定端口的流量，转发至远程主机可以访问到的指定地址和端口。通常使用此方法来访问远程主机内网中，某一个不出网的服务，或者将该服务映射到公网。

使用格式：`ssh -L [本地监听地址:]本地监听端口:目标主机:目标端口 -N [用户名@]SSH服务器`

### Example: Access the target intranet service through the SSH tunnel

使用 ssh 本地转发，将访问本地端口的流量，通过 ssh 代理服务器，转发至目标服务器端口上：

```
┌──(root㉿kali)-[~]
└─# ssh -L 0.0.0.0:80:172.16.10.10:8000 -CfgN root@192.168.70.139
```

此时可以通过访问 kali 的 80 端口，来访问目标内网主机的 8000 端口上的服务：

```
┌──(root㉿kali)-[~]
└─# curl http://localhost:80
```

## Remote Forwarding (Reverse Tunneling)

会将远程 SSH 服务端上指定端口的流量转发到本地主机（SSH 客户端）的端口上。通常用于把本地机器的服务，给远程主机，以及远程主机内网中的其它机器使用。

使用格式：`ssh -R remote-port:local-host:local-port -N [user@]remote-host`

### Example: Forward traffic from a port on the remote host to a port on your local machine

在 kali 本地 80 端口开启一个 http 服务：

```
┌──(root㉿kali)-[~]
└─# impacket-ntlmrelayx
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMTP loaded..
[*] Running in reflection mode
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
[*] HTTPD(80): Client requested path: /
```

使用 ssh 远程转发：

```
┌──(root㉿kali)-[~]
└─# ssh -R 7999:localhost:80 -CfgN root@192.168.70.139
```

此时在远程的 centos 主机上，可以通过访问本地的 7999 端口，来访问 kali 主机的 80 端口。

```
[root@centos ~]# curl http://127.0.0.1:7999
```

但其它的主机并不能通过 centos 的 7999 端口来访问到 kali。

> 注：这是由于在 ssh 远程转发中，远程代理主机 centos 默认只能监听 `127.0.0.1` 地址，如果想要其监听 `0.0.0.0` 地址，需要修改 sshd 的配置文件 `vim /etc/ssh/sshd_config`，开启 `GatewayPorts yes` 选项，重启 ssh 服务 `systemctl restart ssh.service`。

所以需要在远程 centos 主机上进行本地端口转发，将 `0.0.0.0:8000` 的流量转发到 `localhost:7999` 上来：

```
[root@centos ~]# nohup socat TCP-LISTEN:8000,reuseaddr,fork TCP:localhost:7999 > /dev/null 2>&1 &
[1] 4131434
```

此时其它的主机可以通过访问 centos 主机的 8000 端口访问到 kali 主机的 80 端口了：

```
┌──(root㉿kali)-[~]
└─# curl http://192.168.70.139:8000
```

在 kali 上关闭 ssh 远程转发的命令：

```
┌──(root㉿kali)-[~]
└─# pkill -f "ssh -R 7999:localhost:80 -CfgN root@192.168.70.139"
```

在 centos 上关闭 nohup 后台运行的命令：

```
[root@centos ~]# kill -9 4131434
[1]+  Killed                  nohup socat TCP-LISTEN:8000,reuseaddr,fork TCP:localhost:7999 > /dev/null 2>&1
```

如果没有权限开启 GatewayPorts 选项，主机上也没有 socat，还可以配合 `ssh -L` 将 `0.0.0.0:8000` 接受的流量转发到本机的 `localhost:7999` 上来：

```
[root@centos ~]# ssh -L 0.0.0.0:8000:localhost:7999 -CfgN root@localhost
```

## Dynamic Forwarding (SOCKS Proxy)

SSH 动态转发是通过 SSH 隧道将流量从本地计算机转发到远程计算机的技术，该功能通过 SOCKS 协议实现。可用于绕过防火墙、访问远程网络资源以及匿名访问互联网等。

使用格式：`ssh -D [bind_address:]port -N [user@]ssh_server`

### Example: Use SSH to open the SOCKS service to access the target intranet

在本地的 1080 端口启动一个 socks 代理服务，通过本地 socks 代理的数据会通过 ssh 先发送给远程代理主机，再由代理主机转发请求至其它主机：

```xml
┌──(root㉿kali)-[/home/kali]
└─# ssh -D 1080 -CfgN root@xx.xx.xx.xx
The authenticity of host 'xx.xx.xx.xx (xx.xx.xx.xx)' can't be established.
ED25519 key fingerprint is SHA256:...
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'xx.xx.xx.xx' (ED25519) to the list of known hosts.

┌──(root㉿kali)-[/home/kali]
└─# vim /etc/proxychains4.conf

┌──(root㉿kali)-[/home/kali]
└─# proxychains4 -q cme smb 172.22.1.15/24
SMB         172.22.1.2      445    DC01             [*] Windows Server 2016 Datacenter 14393 x64 (name:DC01) (domain:xiaorang.lab) (signing:True) (SMBv1:True)
SMB         172.22.1.18     445    XIAORANG-OA01    [*] Windows Server 2012 R2 Datacenter 9600 x64 (name:XIAORANG-OA01) (domain:xiaorang.lab) (signing:False) (SMBv1:True)
SMB         172.22.1.21     445    XIAORANG-WIN7    [*] Windows Server 2008 R2 Enterprise 7601 Service Pack 1 x64 (name:XIAORANG-WIN7) (domain:xiaorang.lab) (signing:False) (SMBv1:True)

```

> Tips：该命令也可以直接在目标机器上执行，并将 ssh 代理主机指定为目标主机自身，在目标机器上开启 socks 代理服务，这样其他人也可以通过目标主机上的 socks 代理访问目标的内网。

可以使用 curl 命令，通过 socks 代理访问内网服务进行测试：

```
curl -x socks5://127.0.0.1:1080 http://172.16.10.10:8000/
```

> 注：如果 socks 代理经常掉，可以尝试修改服务器的 sshd 配置，开启 `TCPKeepAlive yes` 选项，以便长时间保持连接。也可以尝试使用 [autossh](https://linux.die.net/man/1/autossh) 命令来自动托管 SSH 服务，该实用程序可以自动创建和重新创建 SSH 会话。

## Extra

### Jump Host

如果只是想通过一台公网的 SSH 主机快速连接其内网中的其它主机，可以通过将公网的 SSH 主机作为跳板主机的方式快速实现。

可以使用以下两种方式实现：

```
ssh -J <jump_host> <destination_host>

ssh -i 秘钥 内网用户@内网地址 -o ProxyCommand='ssh 跳板机用户@跳板机地址 -W %h:%p'
```

### sshuttle

[sshuttle](https://github.com/sshuttle/sshuttle) 工具可以通过 SSH 连接来快速实现全局 SOCKS 代理。

> 注：虽然使用该工具不需要在远程服务器上安装 sshuttle，但需要远程服务器有可用的 python。sshuttle 会自动上传并运行其源代码到远程 python 解释器。

使用如下命令，将捕获发送至指定网段的流量，通过 SSH 隧道进行转发：

```
sshuttle --dns -r username@sshserver 10.0.0.0/8 172.16.0.0/16
```

> 注：使用 `0.0.0.0/0` 表示需要转发本地所有请求，可以缩写成 `0/0`。

| 选项                                            | 描述                                                                          |
| ----------------------------------------------- | ----------------------------------------------------------------------------- |
| 位置参数 IP/MASK[:PORT[-PORT]]...               | 捕获并转发到这些子网的流量（以空格分隔）                                      |
| -r , --remote [USERNAME[:PASSWORD]@]ADDR[:PORT] | 传入 SSH 服务器地址                                                           |
| -x, --exclude IP/MASK[:PORT[-PORT]]             | 排除指定的子网（可以多次使用）                                                |
| --dns                                           | 捕获本地 DNS 请求并转发到远程 DNS 服务器                                      |
| --to-ns IP[:PORT]                               | 转发请求的 DNS 服务器；如果未指定，则默认为远程端 /etc/resolv.conf 中的服务器 |
| -H, --auto-hosts                                | 持续扫描远程主机名并更新本地 /etc/hosts                                       |
| -N, --auto-nets                                 | 自动确定要路由的子网                                                          |
| -D, --daemon                                    | 作为守护进程在后台运行                                                        |
| -v, --verbose                                   | 增加调试消息的详细程度（可以多次使用）                                        |
| --no-latency-control                            | 牺牲延迟来提高带宽基准                                                        |

## References

- SSH Tunneling: Examples, Command, Server Config  
  [https://www.ssh.com/academy/ssh/tunneling-example](https://www.ssh.com/academy/ssh/tunneling-example)
- Sakshyam Shah - SSH Tunneling Explained  
  [https://goteleport.com/blog/ssh-tunneling-explained/](https://goteleport.com/blog/ssh-tunneling-explained/)
- Harttle - SSH 配置端口转发  
  [https://harttle.land/2022/05/02/ssh-port-forwarding.html](https://harttle.land/2022/05/02/ssh-port-forwarding.html)
- Linuxize - How to Set up SSH Tunneling (Port Forwarding)  
  [https://linuxize.com/post/how-to-setup-ssh-tunneling/](https://linuxize.com/post/how-to-setup-ssh-tunneling/)
- awesome-tunneling  
  [https://github.com/anderspitman/awesome-tunneling](https://github.com/anderspitman/awesome-tunneling)
