---
layout: post
title: BloodHound 域环境分析
category: [Active Directory]
tags: [active directory pentesting, bloodhound]
---

## BloodHound Collection

在域内主机中，使用 [BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound) 以当前域机器身份向域控发送请求，采集域环境信息：

```console
PS C:\Users\wenshao\Desktop> .\SharpHound.exe -c all
2023-05-18T14:27:27.2072983+08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-05-18T14:27:27.3799607+08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-05-18T14:27:27.3957557+08:00|INFORMATION|Initializing SharpHound at 14:27 on 2023/5/18
2023-05-18T14:27:27.5525204+08:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-05-18T14:27:27.7100612+08:00|INFORMATION|Beginning LDAP search for xiaorang.lab
2023-05-18T14:27:27.7570758+08:00|INFORMATION|Producer has finished, closing LDAP channel
2023-05-18T14:27:27.7725786+08:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-05-18T14:27:58.4591622+08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2023-05-18T14:28:12.5330660+08:00|INFORMATION|Consumers finished, closing output channel
2023-05-18T14:28:12.5988949+08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-05-18T14:28:12.7316697+08:00|INFORMATION|Status: 166 objects finished (+166 3.688889)/s -- Using 43 MB RAM
2023-05-18T14:28:12.7316697+08:00|INFORMATION|Enumeration finished in 00:00:45.0209904
2023-05-18T14:28:12.8119456+08:00|INFORMATION|Saving cache with stats: 124 ID to type mappings.
 126 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-05-18T14:28:12.8275552+08:00|INFORMATION|SharpHound Enumeration Completed at 14:28 on 2023/5/18! Happy Graphing!
```

在域外，使用 [fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) 以指定的域用户身份凭据，远程采集域环境信息：

```console
root@kali:~$ proxychains4 -q python3 bloodhound.py -u "XIAORANG-EXC01$" --hashes 33e36d2a4609e3d963b8c29a3fd664bc:33e36d2a4609e3d963b8c29a3fd664bc -d xiaorang.lab -dc XIAORANG-WIN16.xiaorang.lab -ns 172.22.3.2 -c All --auth-method ntlm --dns-tcp --zip
INFO: Found AD domain: xiaorang.lab
INFO: Connecting to LDAP server: XIAORANG-WIN16.xiaorang.lab
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: XIAORANG-WIN16.xiaorang.lab
INFO: Found 28 users
INFO: Found 73 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 22 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: XIAORANG-PC.xiaorang.lab
INFO: Querying computer: XIAORANG-EXC01.xiaorang.lab
INFO: Querying computer: XIAORANG-WIN16.xiaorang.lab
INFO: Done in 00M 19S
INFO: Compressing output into 20230310182011_bloodhound.zip
```

在域外，也可以使用 [RustHound](https://github.com/NH-RED-TEAM/RustHound) 采集域环境信息：

```
root@kali:~$ rusthound -d rebound.htb -u 'oorend@rebound' -p '1GR8t@$$4u' -i 10.129.55.104 --zip --ldaps
---------------------------------------------------
Initializing RustHound at 22:53:39 on 01/25/24
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2024-01-25T14:53:39Z INFO  rusthound] Verbosity level: Info
[2024-01-25T14:53:40Z INFO  rusthound::ldap] Connected to REBOUND.HTB Active Directory!
[2024-01-25T14:53:40Z INFO  rusthound::ldap] Starting data collection...
[2024-01-25T14:53:43Z INFO  rusthound::ldap] All data collected for NamingContext DC=rebound,DC=htb
[2024-01-25T14:53:43Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2024-01-25T14:53:43Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2024-01-25T14:53:43Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2024-01-25T14:53:43Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] 16 users parsed!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] 61 groups parsed!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] 1 computers parsed!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] 2 ous parsed!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] 1 domains parsed!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] 2 gpos parsed!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] 21 containers parsed!
[2024-01-25T14:53:43Z INFO  rusthound::json::maker] .//20240125225343_rebound-htb_rusthound.zip created!

RustHound Enumeration Completed at 22:53:43 on 01/25/24! Happy Graphing!
```

在 -c 参数中，可以查看到可以采集到域内的哪些信息：

| 参数                     | 参数值                                                                                                                                                                                                                       |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -c, \--collectionmethods | (Default: Default) Collection Methods: Group, LocalGroup, LocalAdmin, RDP, DCOM, PSRemote, Session, Trusts, ACL, Container, ComputerOnly, GPOLocalGroup, LoggedOn, ObjectProps, SPNTargets, UserRights, Default, DCOnly, All |

常用可选参数：

| 参数值        | 简要描述                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Default       | You can specify default collection, or don’t use the CollectionMethods option and this is what SharpHound will do. Default collection includes Active Directory security group membership, domain trusts, abusable permissions on AD objects, OU tree structure, Group Policy links, the most relevant AD object properties, local groups from domain-joined Windows systems, and user sessions. |
| All           | Performs all collection methods except for GPOLocalGroup.                                                                                                                                                                                                                                                                                                                                        |
| DCOnly        | Collects data ONLY from the domain controller, will not touch other domain-joined Windows systems. Collects AD security group memberships, domain trusts, abusable permissions on AD objects, OU tree structure, Group Policy links, the most relevant AD object properties, and will attempt to correlate Group Policy-enforced local groups to affected computers.                             |
| ComputerOnly  | Collects user sessions (Session) and local groups (LocalGroup) from domain-joined Windows systems. Will NOT collect the data collected with the DCOnly collection method.                                                                                                                                                                                                                        |
| Session       | Just does user session collection. You will likely couple this with the `--Loop` option. See SharpHound examples below for more info on that.                                                                                                                                                                                                                                                    |
| LoggedOn      | Does session collection using the privileged collection method. Use this if you are running as a user with local admin rights on lots of systems for the best user session data.                                                                                                                                                                                                                 |
| Group         | Just collect security group memberships from Active Directory                                                                                                                                                                                                                                                                                                                                    |
| ACL           | Just collect abusable permissions on objects in Active Directory                                                                                                                                                                                                                                                                                                                                 |
| GPOLocalGroup | Just attempt GPO to computer correlation to determine members of the relevant local groups on each computer in the domain. Doesn’t actually touch domain-joined systems, just gets info from domain controllers                                                                                                                                                                                  |
| Trusts        | Just collect domain trusts                                                                                                                                                                                                                                                                                                                                                                       |
| Container     | Just collect the OU tree structure and Group Policy links                                                                                                                                                                                                                                                                                                                                        |
| LocalGroup    | Just collect the members of all interesting local groups on each domain-joined computer. Equivalent for LocalAdmin + RDP + DCOM + PSRemote                                                                                                                                                                                                                                                       |
| LocalAdmin    | Just collect the members of the local Administrators group on each domain-joined computer                                                                                                                                                                                                                                                                                                        |
| RDP           | Just collect the members of the Remote Desktop Users group on each domain-joined computer                                                                                                                                                                                                                                                                                                        |
| DCOM          | Just collect the members of the Distributed COM Users group on each domain-joined computer                                                                                                                                                                                                                                                                                                       |
| PSRemote      | Just collect the members of the Remote Management group on each domain-joined computer                                                                                                                                                                                                                                                                                                           |
| ObjectProps   | Performs Object Properties collection for properties such as LastLogon or PwdLastSet                                                                                                                                                                                                                                                                                                             |

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/988e044b8fa716d6.png)
_Image credit: [https://twitter.com/SadProcessor](https://twitter.com/SadProcessor)_

## BloodHound Deployment

安装命令：

```
sudo apt-get install bloodhound
sudo neo4j console
```

> 注：需要访问 http://localhost:7474/browser/ 修改默认密码 neo4j/neo4j

安装并配置完成后，在终端输入 bloodhound 启动即可。

## Bloodhound Custom Queries

GitHub 上的 BloodHound 自定义查询项目：

1. [CompassSecurity/BloodHoundQueries](https://github.com/CompassSecurity/BloodHoundQueries)
2. [ZephrFish/Bloodhound-CustomQueries](https://github.com/ZephrFish/Bloodhound-CustomQueries)
3. [hausec/Bloodhound-Custom-Queries](https://github.com/hausec/Bloodhound-Custom-Queries)
4. [seajaysec/customqueries.json](https://gist.github.com/seajaysec/a4d4a545047a51053d52cba567f78a9b)

可以在 Linux 中运行以下命令来快速安装自定义查询：

```
# Windows(cmd): %APPDATA%\bloodhound\customqueries.json
# Windows(powershell): $env:APPDATA\bloodhound\customqueries.json
# Linux: ~/.config/bloodhound/customqueries.json

cd ~/.config/bloodhound/
curl -o "customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json"
```

对来自不同数据集的自定义 BloudHound 查询，可以使用 [Acceis/bqm](https://github.com/Acceis/bqm) 删除重复数据，并将它们合并到一个 customqueries.json 文件中：

```console
root@kali:~# gem install bqm --no-wrapper

root@kali:~# bqm -o ./customqueries.json -i customqueries_1.json,customqueries_2.json,customqueries_3.json
[+] Fetching and merging datasets
[+] Removing duplicates
[+] All queries have been merged in ./customqueries.json

root@kali:~# cp ./customqueries.json ~/.config/bloodhound/customqueries.json
```

## BloodHound Attack Paths and Relationships

| **BloodHound Relationship** | **Local Group Membership** |
| --------------------------- | -------------------------- |
| CanRDP                      | Remote Desktop Users       |
| AdminTo                     | Administrators             |
| ExecuteDCOM                 | Remote COM Users           |
| CanPSRemote                 | Remote Management Users    |

## Issue

### DNS Operation Timed Out

在通过代理，使用 bloodhound-python 远程收集域环境信息时，可能会遇见 `dns.resolver.LifetimeTimeout` 报错。

```
root@kali:~# proxychains4 -q bloodhound-python -u saul -p 'admin!@#45' -d redteam.red -dc owa.redteam.red -c all -ns 10.10.10.8 --zip -v
DEBUG: Authentication: username/password
DEBUG: Resolved collection methods: localadmin, dcom, container, session, group, objectprops, rdp, trusts, psremote, acl
DEBUG: Using DNS to retrieve domain information
DEBUG: Querying domain controller information from DNS
DEBUG: Using domain hint: redteam.red
Traceback (most recent call last):
  File "/usr/bin/bloodhound-python", line 33, in <module>
    sys.exit(load_entry_point('bloodhound==1.6.1', 'console_scripts', 'bloodhound-python')())
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/bloodhound/__init__.py", line 303, in main
    ad.dns_resolve(domain=args.domain, options=args)
  File "/usr/lib/python3/dist-packages/bloodhound/ad/domain.py", line 645, in dns_resolve
    q = self.dnsresolver.query(query, 'SRV', tcp=self.dns_tcp)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 1262, in query
    return self.resolve(
           ^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 1204, in resolve
    timeout = self._compute_timeout(start, lifetime, resolution.errors)
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/dns/resolver.py", line 988, in _compute_timeout
    raise LifetimeTimeout(timeout=duration, errors=errors)
dns.resolver.LifetimeTimeout: The resolution lifetime expired after 3.202 seconds: Server 10.10.10.8 UDP port 53 answered The DNS operation timed out.; Server 10.10.10.8 UDP port 53 answered The DNS operation timed out.

```

在 [DNS Timeout Issue](https://github.com/fox-it/BloodHound.py/issues/29) 中查看的回答：可以优先尝试使用 `--dns-timeout` 参数（默认值：3 秒）指定，指定 DNS 查询超时时间。

如果也无法成功，就需要使用 [dnschef](https://github.com/iphelix/dnschef)，在其配置文件的 `[SRV]` 配置中，添加一个条配置，将指定的域名解析指向域控：

```ini
[SRV]
; FORMAT: priority weight port target
*.*.thesprawl.org=0 5 5060 sipserver.fake.com
*.*.*.*.xiaorang.lab=0 5 5060 DC01.xiaorang.lab
```

也可以直接尝试直接在命令行中指定，但经常还是失败：

```console
root@kali:~# dnschef --fakeip 172.22.8.15 --fakedomains *.xiaorang.lab
```

使用配置文件稳妥：

```console
root@kali:~# dnschef --fakeip 10.10.10.8 --file /usr/share/doc/dnschef/dnschef.ini
```

这个问题在使用 CME 的时候也经常遇见：

```console
root@kali:~# proxychains4 -q cme ldap owa.redteam.red -u 'administrator' -p 'Admin!@#45' -d redteam.red --bloodhound -ns 10.10.10.8 --collection All
SMB         owa.redteam.red 445    OWA              [*] Windows Server 2008 R2 Datacenter 7601 Service Pack 1 x64 (name:OWA) (domain:redteam.red) (signing:True) (SMBv1:True)
LDAP        owa.redteam.red 389    OWA              [+] redteam.red\administrator:Admin!@#45 (Pwn3d!)
LDAP        owa.redteam.red 389    OWA              Resolved collection methods: container, psremote, session, trusts, objectprops, group, acl, rdp, localadmin, dcom
[14:24:19] ERROR    Exception while calling proto_flow() on target owa.redteam.red: The resolution lifetime expired after 3.202 seconds: Server 10.10.10.8 UDP port 53 answered The DNS operation timed out.;       connection.py:85
                    Server 10.10.10.8 UDP port 53 answered The DNS operation timed out.
                    ╭───────────────────────────────────────────────────────────────────────────── Traceback (most recent call last) ─────────────────────────────────────────────────────────────────────────────╮
                    │ ......                                                                                           │
                    ╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                    LifetimeTimeout: The resolution lifetime expired after 3.202 seconds: Server 10.10.10.8 UDP port 53 answered The DNS operation timed out.; Server 10.10.10.8 UDP port 53 answered The DNS
                    operation timed out.
```

在 CME 中使用，还需要修改 `/etc/hosts` 域控和 IP 的绑定关系 `172.22.8.15     DC01.xiaorang.lab`：（将全部主机添加对应关系应该也能解决这个问题）

```console
root@kali:~# proxychains4 -q cme ldap DC.xiaorang.lab -u wangyun -p Adm12geC -d xiaorang.lab --bloodhound -ns 127.0.0.1 --collection
All
SMB         DC.xiaorang.lab 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:xiaorang.lab) (signing:True) (SMBv1:False)
LDAP        DC.xiaorang.lab 389    DC               [+] xiaorang.lab\wangyun:Adm12geC
LDAP        DC.xiaorang.lab 389    DC               Resolved collection methods: container, session, localadmin, trusts, objectprops, acl, dcom, rdp, group, psremote
LDAP        DC.xiaorang.lab 389    DC               Done in 00M 08S
LDAP        DC.xiaorang.lab 389    DC               Compressing output into /root/.cme/logs/DC_DC.xiaorang.lab_2023-08-16_234118bloodhound.zip
```

## References

- Make the most out of BloodHound  
  [https://blog.compass-security.com/2020/07/make-the-most-out-of-bloodhound/](https://blog.compass-security.com/2020/07/make-the-most-out-of-bloodhound/)
- BloodHound Support  
  [https://support.bloodhoundenterprise.io/hc/en-us](https://support.bloodhoundenterprise.io/hc/en-us)
- BloodHound Cypher Cheatsheet  
  [https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
- Scanning for Active Directory Privileges & Privileged Accounts  
  [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- Bloodhound Cheatsheet – Custom Queries, Neo4j, etc.  
  [https://infinitelogins.com/2022/01/28/bloodhound-cheatsheet-custom-queries-neo4j-lookups/](https://infinitelogins.com/2022/01/28/bloodhound-cheatsheet-custom-queries-neo4j-lookups/)
- BloodHound: Six Degrees of Domain Admin  
  [https://bloodhound.readthedocs.io/en/latest/](https://bloodhound.readthedocs.io/en/latest/)
- BloodHound 使用指南  
  [https://forum.90sec.com/t/topic/1633](https://forum.90sec.com/t/topic/1633)
