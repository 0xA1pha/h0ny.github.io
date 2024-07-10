---
layout: post
title: Burp Suite and Android Emulator Setup - Windows
category: APP
tags: [android]
---

## ENV Configuration

在进行以下配置前，请先确保电脑上有配置 JAVA 环境。

---

如果你不需要使用 Android Studio 的全部功能，可以只下载以下关键组件：

- [Android SDK Command-Line Tools](https://developer.android.com/studio)
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools)
- [Android Emulator](https://developer.android.com/studio/emulator_archive)

设置环境变量：

| 名称             | 路径                                    |
| ---------------- | --------------------------------------- |
| ANDROID_HOME     | C:\Users\hony\AppData\Local\Android     |
| ANDROID_SDK_ROOT | C:\Users\hony\AppData\Local\Android\Sdk |

## Download Android SDK

当下载好所需的工具并配置好环境变量后，还需要下载 Android SDK 镜像才能创建 Android Virtual Device (AVD)。

---

查看可以下载的 Android SDK 镜像：（还需要注意的是，描述中一定要有 `Google APIs` 关键字，否则后续可能无法 ROOT 它）

```console
PS C:\> sdkmanager --list --sdk_root="C:\Users\hony\AppData\Local\Android\Sdk" | findstr "system-images"
  ...
  system-images;android-34-ext10;google_apis_playstore;arm64-v8a                           | 2             | Google Play ARM 64 v8a System Image
  system-images;android-34-ext10;google_apis_playstore;x86_64                              | 2             | Google Play Intel x86_64 Atom System Image
  system-images;android-34-ext8;google_apis_playstore;arm64-v8a                            | 2             | Google Play ARM 64 v8a System Image
  system-images;android-34-ext8;google_apis_playstore;x86_64                               | 2             | Google Play Intel x86_64 Atom System Image
  system-images;android-34;android-tv;arm64-v8a                                            | 2             | Android TV ARM 64 v8a System Image
  system-images;android-34;android-tv;x86                                                  | 2             | Android TV Intel x86 Atom System Image
  system-images;android-34;aosp_atd;arm64-v8a                                              | 2             | AOSP ATD ARM 64 v8a System Image
  system-images;android-34;aosp_atd;x86_64                                                 | 2             | AOSP ATD Intel x86_64 Atom System Image
  system-images;android-34;default;arm64-v8a                                               | 4             | ARM 64 v8a System Image
  system-images;android-34;default;x86_64                                                  | 4             | Intel x86_64 Atom System Image
  system-images;android-34;google-tv;arm64-v8a                                             | 2             | Google TV ARM 64 v8a System Image
  system-images;android-34;google-tv;x86                                                   | 2             | Google TV Intel x86 Atom System Image
  system-images;android-34;google_apis;arm64-v8a                                           | 12            | Google APIs ARM 64 v8a System Image
  system-images;android-34;google_apis;x86_64                                              | 12            | Google APIs Intel x86_64 Atom System Image
  system-images;android-34;google_apis_playstore;x86_64                                    | 12            | Google Play Intel x86_64 Atom System Image
  system-images;android-TiramisuPrivacySandbox;google_apis;arm64-v8a                       | 1             | Google APIs ARM 64 v8a System Image
  system-images;android-TiramisuPrivacySandbox;google_apis;x86_64                          | 1             | Google APIs Intel x86_64 Atom System Image
  system-images;android-TiramisuPrivacySandbox;google_apis_playstore;x86_64                | 9             | Google Play Intel x86_64 Atom System Image
  system-images;android-UpsideDownCakePrivacySandbox;google_apis_playstore;x86_64          | 3             | Google Play Intel x86_64 Atom System Image
  system-images;android-VanillaIceCream;google_apis;arm64-v8a                              | 3             | Google APIs ARM 64 v8a System Image
  system-images;android-VanillaIceCream;google_apis;x86_64                                 | 3             | Google APIs Intel x86_64 Atom System Image
  system-images;android-VanillaIceCream;google_apis_playstore;arm64-v8a                    | 3             | Google Play ARM 64 v8a System Image
  system-images;android-VanillaIceCream;google_apis_playstore;x86_64                       | 3             | Google Play Intel x86_64 Atom System Image
```

下载并查看安装的镜像：

```console
PS C:\> sdkmanager "system-images;android-34;google_apis;x86_64" --sdk_root=C:\Users\hony\AppData\Local\Android\Sdk
[=======================================] 100% Unzipping... x86_64/ramdisk.img

PS C:\> sdkmanager --list_installed
[=======================================] 100% Fetch remote repository...
Installed packages:
  Path                                         | Version | Description                          | Location
  -------                                      | ------- | -------                              | -------
  build-tools;34.0.0                           | 34.0.0  | Android SDK Build-Tools 34           | build-tools\34.0.0
  emulator                                     | 34.1.19 | Android Emulator                     | emulator
  platform-tools                               | 35.0.0  | Android SDK Platform-Tools           | platform-tools
  platforms;android-34                         | 3       | Android SDK Platform 34              | platforms\android-34
  sources;android-34                           | 2       | Sources for Android 34               | sources\android-34
  system-images;android-34;default;x86_64      | 4       | Intel x86_64 Atom System Image       | system-images\android-34\default\x86_64
```

指定镜像和设备，创建 Android Virtual Device (AVD)：

```console
PS C:\> avdmanager list device | findstr pixel
id: 31 or "pixel_7"
id: 32 or "pixel_7_pro"

PS C:\> avdmanager --verbose create avd --name "pixel_7_pro_api34" --package "system-images;android-34;google_apis;x86_64" --device "pixel_7_pro" --sdcard 9000M --force
[=======================================] 100% Fetch remote repository...
Auto-selecting single ABI x86_64
```

查看当前已经创建的 AVD：

```console
PS C:\> emulator -list-avds
INFO    | Storing crashdata in: C:\Users\hony\AppData\Local\Temp\\AndroidEmulator\emu-crash-34.1.19.db, detection is enabled for process: 34792
pixel_7_pro_api34

PS C:\> avdmanager list avd
Available Android Virtual Devices:
    Name: pixel_7_pro_api34
  Device: pixel_7_pro (Google)
    Path: C:\Users\hony\.android\avd\pixel_7_pro_api34.avd
  Target: Default Android System Image
          Based on: Android 14.0 ("UpsideDownCake") Tag/ABI: default/x86_64
  Sdcard: 512 MB
```

启动指定的 AVD：

```console
PS C:\> emulator -writable-system -no-snapshot-load -qemu -avd "pixel_7_pro_api34"
```

## HTTP/HTTPS Proxy

想要将 Android Virtual Device 的 HTTP/HTTPS 流量代理到 Burp Suite 通常需要向设备中写入证书。

注：如果使用 [HTTP Toolkit](https://httptoolkit.com/) 抓包可以省去这些麻烦。

---

证书配置：对 burp 证书进行格式转换

```console
root@kali:~# openssl x509 -inform DER -in cacert.der -out cacert.pem

root@kali:~# openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
9a5ba575

root@kali:~# cp cacert.pem 9a5ba575.0
```

在高版本的 Android 系统中，即使是 root 权限也不能向 `/system/etc/security/cacerts/` 目录写入内容：

```console
PS C:\Users\hony> adb devices
List of devices attached
emulator-5554   device

PS C:\> adb root emulator-5554
restarting adbd as root
PS C:\> adb push 9a5ba575.0 /system/etc/security/cacerts/
9a5ba575.0: 1 file pushed, 0 skipped. 5.7 MB/s (4322 bytes in 0.001s)
adb: error: failed to copy '9a5ba575.0' to '/system/etc/security/cacerts/9a5ba575.0': remote couldn't create file: Read-only file system
```

使用 adb 禁用验证并重启 AVD，此时再将设备磁盘重新挂载后就会有写入权限：

```console
PS C:\> adb kill-server
PS C:\> adb disable-verity
Successfully disabled verity

virtual bool android::fiemap::ImageManagerBinder::MapImageDevice(const std::string &, const std::chrono::milliseconds &, std::string *) binder returned: Failed to map
[libfs_mgr] could not map scratch image
Failed to allocate scratch on /data, fallback to use free space on super
enabling overlayfs
Reboot the device for new settings to take effect

PS C:\> adb reboot
PS C:\> adb root
adb: unable to connect for root: device offline
PS C:\> adb root
restarting adbd as root

PS C:\> adb push 9a5ba575.0 /system/etc/security/cacerts/
9a5ba575.0: 1 file pushed, 0 skipped. 6.2 MB/s (4322 bytes in 0.001s)
adb: error: failed to copy '9a5ba575.0' to '/system/etc/security/cacerts/9a5ba575.0': remote couldn't create file: Read-only file system

PS C:\> adb remount
Successfully disabled verity
Remounted /system as RW
Remounted /vendor as RW
Remounted /product as RW
Remounted /system_dlkm as RW
Remounted /system_ext as RW
Remount succeeded

PS C:\> adb push 9a5ba575.0 /system/etc/security/cacerts/
9a5ba575.0: 1 file pushed, 0 skipped. 5.8 MB/s (4322 bytes in 0.001s)

PS C:\> adb shell
emu64xa:/ # chmod 644 /system/etc/security/cacerts/9a5ba575.0
emu64xa:/ # reboot
```

网络配置：关闭【WIFI】，打开【T-Mobile/移动网络】

![alt text](<https://raw.githubusercontent.com/h0ny/repo/main/images/b9126f178611c607.png>)

在 Android Emulator 设置中配置系统代理，为 Windows 主机的 IP 地址：

![alt text](<https://raw.githubusercontent.com/h0ny/repo/main/images/a2ebf52c1d6c9097.png>)

Windows ipconfig 命令查看网络地址：

```
无线局域网适配器 WLAN:

   连接特定的 DNS 后缀 . . . . . . . : 
   IPv4 地址 . . . . . . . . . . . . : 192.168.199.181
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 192.168.199.1
```

也可以使用以下方式，在 AVD 中配置 WIFI 的代理地址，配置完成后重启模拟器后即可上网：

```
// 插入
sqlite3 /data/data/com.android.providers.settings/databases/settings.db "INSERT INTO system VALUES(99,'http_proxy','10.10.26.252:1080')"

// 查询
sqlite3 /data/data/com.android.providers.settings/databases/settings.db "SELECT * FROM system"

// 删除
sqlite3 /data/data/com.android.providers.settings/databases/settings.db "DELETE FROM system WHERE _id=99"
```

> 注：sqlite 是 Android 系统采用的微型数据库，可以通过写入数据到数据库的方式来更新系统代理设置。（未进行测试）

安装 APK：

```
adb install app.apk
```

> 注：如果在安装 APK 的时候出现错误 `INSTALL_FAILED_NO_MATCHING_ABIS` 那就是 AVD 架构和 APK 文件不适配，需要换下 AVD 的架构。

## Extra1: WSA

如果你使用的是高贵的 Windows 😎，那么你可以方便的使用 WSA (Windows Subsystem for Android) 来安装 APK 安卓安装包。

WSA 用户可以使用 [WSA 工具箱 - 微软应用商店](https://apps.microsoft.com/detail/9PPSP2MKVTGT)来更加方便的管理你的安卓应用。

## References and Links

- [Configuring an Android device to work with Burp Suite Professional - PortSwigger](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device)
- [Burp Suite Android Emulator: Complete Guide](https://infosecwriteups.com/burp-suite-android-emulator-5c030d420394)
- [How to configure Burp Suite proxy with an Android emulator?](https://secabit.medium.com/how-to-configure-burp-proxy-with-an-android-emulator-31b483237053)
- [Android 11 tightens restrictions on CA certificates](https://httptoolkit.com/blog/android-11-trust-ca-certificates/)



