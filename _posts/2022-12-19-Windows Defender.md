---
layout: post
title: Windows Defender
category: Windows
tags: [windows defender, antivirus]
---

随着 Windows 的安全性在不断的提升，彻底关闭 Windows Defender 变得越来越困难，即使手动关闭 “篡改防护 (Tamper Protection)” 并获取到了 TrustedInstaller 权限也很难将其关闭。

并不推荐完全关闭杀软，因为这样做不仅不容易成功，而且动静很大，用户肯定会发现（关闭后会通知栏会弹出信息，告知用户 defender 已经关闭了）。一般情况，添加排除项目或者关闭实时扫描即可。

## 获取主机杀软信息

利用 WMI 获取主机杀软信息：

```console
C:\Users\test\Desktop>WMIC.exe /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get /Format:List

displayName=Windows Defender
instanceGuid={D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
pathToSignedProductExe=windowsdefender://
pathToSignedReportingExe=%ProgramFiles%\Windows Defender\MsMpeng.exe
productState=397568
timestamp=Wed, 07 Sep 2022 09:05:13 GMT

C:\Users\test\Desktop>:: 只显示 Anti-Viruses 名称
C:\Users\test\Desktop>WMIC.exe /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct Get DisplayName | findstr /V /B /C:displayName || echo No Antivirus installed
Windows Defender

C:\Users\test\Desktop>:: 在 PowerShell 中使用 CimCmdlets 查询杀软信息
C:\Users\test\Desktop>powershell -command "(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName"
Windows Defender
Kaspersky
```

## 管理 Microsoft Defender - CMD

> 注：直接修改 Defender 相关注册表，均需要 SYSTEM 权限。

查看所有排除项：

```
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s
```

查看“篡改防护”（返回结果中的 数值 5 代表开启，数值 4 代表关闭）：

```
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection"
```

添加路径排除项：

```
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "c:\temp" /d 0 /t REG_DWORD /f
```

关闭和开启 DEP（Data Execution Prevention，数据执行防护）：

```
# 关闭DEP
bcdedit.exe /set {current} nx AlwaysOff
# 开启DEP
bcdedit.exe /set {current} nx OptIn
```

wmic 向 defender 添加排除项：

```
WMIC /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionPath=\"
WMIC /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionPath=\"\Temp\\"
WMIC /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionExtension=\".dll\"
WMIC /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionProcess=\"rundll32.exe\"
```

## 管理 Microsoft Defender - PowerShell

检查 Microsoft Defender 防病毒服务 (WinDefend)、Windows 安全服务 (SecurityHealthService) 和安全中心 (wscsvc) 的服务状态：

```
PS C:\WINDOWS\system32> Get-Service Windefend, SecurityHealthService, wscsvc| Select Name,DisplayName, Status

Name                  DisplayName                           Status
----                  -----------                           ------
SecurityHealthService Windows 安全中心服务                 Running
Windefend             Microsoft Defender Antivirus Service Stopped
wscsvc                安全中心                             Running
```

> 注：如果在 windows 系统被其它杀软接管时 Windefend 服务处于 Stopped 状态，无法使用 powershell 命令对 windows defender 进行更改操作，这与用户权限无关。

使用 PowerShell 操作 Microsoft Defender 常用命令 ：

```powershell
# 查看排除项
Get-MpPreference | select ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress | Format-List
# 增加路径排除项
Add-MpPreference -ExclusionPath "C:\temp"
# 删除路径排除项
Remove-MpPreference -ExclusionPath "C:\temp"
# 关闭实时保护
Set-MpPreference -DisableRealtimeMonitoring $true
# 关闭 Windefend 服务（不建议使用该命令进行操作）
Stop-Service -Name Windefend
```

在通过 reg add 命令直接修改注册表添加排除项时，需要 SYSTEM 权限，而在 PowerShell 中使用 [Microsoft Defender Antivirus Cmdlets](https://learn.microsoft.com/en-us/powershell/module/defender/) 只需要 Administratior 权限，但二者实际操作都是修改注册表。

下面是在管理员权限下进行的测试，使用 reg add 命令直接修改注册表失败了，但使用 PowerShell cmdlets 命令添加排除项，注册表成功被修改了：

```console
C:\Windows\System32>reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /s


C:\Windows\System32>reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "c:\temp" /d 0 /t REG_DWORD /f
错误: 拒绝访问。

C:\Windows\System32>powershell "Add-MpPreference -ExclusionPath 'C:\temp'"

C:\Windows\System32>reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /s

HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
    C:\temp    REG_DWORD    0x0


C:\Windows\System32>
```

## 管理 Microsoft Defender - MpCmdRun

可以使用专用命令行工具 mpcmdrun.exe 在 Microsoft Defender 防病毒中执行各种功能。

MpCmdRun.exe 文件所在位置 1：

```
dir "C:\ProgramData\Microsoft\Windows Defender\Platform\" /od /ad /b
# 得到 Windows Defender 版本 <antimalware platform version>

"C:\ProgramData\Microsoft\Windows Defender\Platform\<antimalware platform version>\MpCmdRun.exe"
```

MpCmdRun.exe 文件所在位置 2：

```console
C:\Users\test\Desktop>echo %ProgramFiles%\Windows Defender\MsMpeng.exe
C:\Program Files\Windows Defender\MsMpeng.exe
```

当 Windows 被其它杀软接管时（Windefend 服务停止状态），使用这些 MpCmdRun 命令都会报错：

```console
# 只存在 Windows Defender 时，正常执行
C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2211.5-0>MpCmdRun -Restore -ListAll
The following items are quarantined:

ThreatName = HackTool:Win32/Cain
      file:C:\Users\test\Downloads\ca_setup.exe quarantined at 2022/12/31 10:18:35 (UTC)

# 由其它杀软接管时，执行报错
C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2211.5-0>MpCmdRun -Restore -ListAll
CmdTool: Failed with hr = 0x800106ba. Check C:\Users\test\AppData\Local\Temp\MpCmdRun.log for more information

C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2211.5-0>
```

### 清空病毒库规则

删除 Windows Defender 中的所有病毒定义，并在完成后等待 1 秒：

```console
PS C:\Windows\system32> # Remove Defender Definitions
PS C:\Windows\system32> & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All; Start-Sleep -Seconds 1

Service Version: 4.18.23070.1004
Engine Version: 1.1.23070.1005
AntiSpyware Signature Version: 1.395.661.0
AntiVirus Signature Version: 1.395.661.0

Starting engine and signature rollback to none...
Done!
PS C:\Windows\system32>
```

> 注：该操作并不会关闭 Windows Defender

### 恢复被隔离的文件

查看被隔离的文件列表：

```
MpCmdRun -Restore -ListAll
```

恢复指定名称的文件至原目录：

```
MpCmdRun -Restore -FilePath C:\temp\mimikatz_trunk.zip
```

恢复所有文件至原目录：

```
MpCmdRun -Restore -All
```

查看指定路径是否位于排除列表中：

```
MpCmdRun -CheckExclusion -path C:\temp
```

## 管理员权限操作技巧

在已经有 Administratior 权限的情况下，可使用 [NSudo - 系统管理工具包](https://github.com/M2TeamArchived/NSudo/blob/master/Readme.zh-CN.md) 获取 TrustedInstaller 权限来执行命令：

```
# 添加 Windows Defender 排除项
NSudoLG.exe -U:T cmd /c "reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "c:\temp" /d 0 /t REG_DWORD /f"
# 关闭 Windows Defender 篡改保护
NSudoLG.exe -U:T cmd /c "reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /d 4 /t REG_DWORD /f"
# 关闭 Windows Defender
NSudoLG.exe -U:T cmd /c "reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t reg_dword /d 1 /f"
# 恢复 Windows Defender
NSudoLG.exe -U:T cmd /c "reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t reg_dword /d 0 /f"
```

> 注：若无 Administratior 权限，会弹出 UAC。

也可以使用 [AdvancedRun](https://www.nirsoft.net/utils/advanced_run.html) 添加 /RunAs 8 参数，以 TrustedInstaller 运行：

```
AdvancedRun.exe /EXEFilename "%windir%\system32\cmd.exe" /CommandLine '/c reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /d 1 /t REG_DWORD /f' /RunAs 8 /Run
```

## 参考文章

- 渗透基础——Windows Defender  
  [https://3gstudent.github.io/渗透基础-Windows-Defender](https://3gstudent.github.io/渗透基础-Windows-Defender)
- How to Disable, Enable, and Manage Microsoft Defender Using PowerShell? – TheITBros  
  [https://theitbros.com/managing-windows-defender-using-powershell/](https://theitbros.com/managing-windows-defender-using-powershell/)
- Manage Microsoft Defender Antivirus in your business  
  [https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configuration-management-reference-microsoft-defender-antivirus?view=o365-worldwide](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configuration-management-reference-microsoft-defender-antivirus?view=o365-worldwide)
- TrustedInstaller, parando Windows Defender  
  [https://www.securityartwork.es/2021/09/27/trustedinstaller-parando-windows-defender/](https://www.securityartwork.es/2021/09/27/trustedinstaller-parando-windows-defender/)
