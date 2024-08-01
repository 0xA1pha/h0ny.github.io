---
layout: post
title: APP 抓包 - Proxifier
category: APP
tags: [android, proxifier]
---

## TL;DR

在对 app 渗透测试的时候，经常会遇见代理检测，代理配置麻烦的问题。

当测试的 app 没有做模拟器检测时，使用 proxifier 对整个模拟器进程的流量进行代理，可以轻松 bypass 代理检测，同时还能避免反复在手机中配置代理。

## Proxifier Configuration

proxifier 配置方法如下，以下使用 mumu 模拟器为例。

---

在活动监视器中，查找到对应的进程，查看文件位置。

`/Applications/MuMuPlayer.app/Contents/MacOS/MuMuEmulator.app/Contents/MacOS/MuMuEmulator`

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/4d1bf7ca20297209.png)

在 proxifier 中找到文件并添加即可。

> 注：mac 中可以使用访达快捷键 shift + command + g 弹出路径栏，输入完整路径。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/553958b4ab4c8bae.png)

配置 mitmproxy 证书至 mumu 模拟器。

```bash
cd ~/.mitmproxy/
hashed_name=`openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.cer | head -1` && cp mitmproxy-ca-cert.cer $hashed_name.0
adb push c8750f0d.0 /system/etc/security/cacerts/c8750f0d.0
```

运行 app，使用 mitmproxy 进行抓包即可。

> 注：此处使用 burp/yakit 进行抓包，遇见少数特殊的 app 可能会出现抓包失败的情况。不知道具体是什么原因，看着也不像因为【双向证书认证】的原因。

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/bee6ec1d0d100403.png)

## References and Links

- https://mumu.163.com/mac/function/20240204/40028_1136777.html
- https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/
- https://itnext.io/how-to-record-replay-http-traffic-in-android-and-ios-apps-db24a5dcc0e
