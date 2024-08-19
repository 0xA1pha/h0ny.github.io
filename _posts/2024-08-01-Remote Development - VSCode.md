---
layout: post
title: Remote Development - VSCode
category: Development
tags: [remote, ssh, vscode]
---

以下是使用 vscode 连接远程 windows 服务器进行开发的配置步骤。（远程写代码是真的痛苦 🥴，能本地还是本地吧。）

在远程 windows 主机安装 ssh 服务端。

> 配置路径：「Setting」>「Apps」>「Optional features」

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/61ac2946c069e2d2.PNG)

此处可以使用以下 powershell 命令来快速完成操作。

```powershell
Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

配置开启 ssh 服务。

```console
PS C:\Users\Administrator> Start-Service sshd
PS C:\Users\Administrator> Set-Service -Name "sshd" -StartupType Automatic
PS C:\Users\Administrator> Get-Service -Name "sshd" | Format-List -Property *

Name                : sshd
RequiredServices    : {}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : True
DisplayName         : OpenSSH SSH Server
DependentServices   : {}
MachineName         : .
ServiceName         : sshd
ServicesDependedOn  : {}
ServiceHandle       : SafeServiceHandle
Status              : Running
ServiceType         : Win32OwnProcess
StartType           : Automatic
Site                :
Container           :

```

在本地 vscode 安装 `Remote - SSH` 插件。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/425dab493eb0d11d.png)

在 vscode 中对 ssh 进行配置后，即可使用账号密码进行连接。

```
Host 192.168.190.139
  HostName 192.168.190.139
  User Administrator
  IdentityFile ~/.ssh/id_rsa
  ForwardAgent yes
```

> 注：如果是连接 Linux 主机，可以在向主机写入公钥后，配置 IdentityFile 字段使用本地的私钥文件进行认证。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/70f74bb9f3e7a326.png)
