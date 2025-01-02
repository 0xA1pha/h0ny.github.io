---
layout: post
title: Windows 中 Java 环境配置技巧
category: Development
tags: [java, windows, javafx]
---

问题描述：开发环境 JDK 版本在 11 以上，但在运行 JavaFX 图形化框架所编写的程序时，通常又会需要使用 JDK 8 环境。因为从 Java 11 开始，由于模块化的原因移除了许多非必须的模块，JavaFX 就在其中。

达到效果：在主机无论是命令行中，还是 JAVA_HOME 所配置的 Java 环境都是 JDK 11 及上环境，仅在使用鼠标双击 .jar 包时使用 JDK 8 环境。

注册表路径：`Computer\HKEY_CLASSES_ROOT\JARFile\Shell\Open\Command`

---

在 Windows 环境下，可以通过注册表的方式，来修改在桌面上双击指定后缀文件，运行的默认打开程序。

修改以下 .reg 文件内容，双击导入即可：

```
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\.jar]
@="jarfile"

[HKEY_CLASSES_ROOT\jarfile]
@="Executable Jar File"

[HKEY_CLASSES_ROOT\jarfile\shell\open\command]
@="\"C:\\Program Files\\Java\\jdk1.8\\bin\\javaw.exe\" -jar \"%1\" %*"

```

也可以通过 Windows CMD 内置命令（built-in commands）[ftype](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftype) 进行配置：

```console
C:\> assoc .jar
.jar=jarfile

C:\> ftype jarfile="C:\Program Files\Java\jdk1.8\bin\javaw.exe" -jar "%1" %*
```

如果你不想下载多个 JDK 可以选择单独下载 [JavaFX](https://gluonhq.com/products/javafx/) 模块，并在运行时添加以下参数：

```
--add-opens javafx.controls/com.sun.javafx.scene.control.skin=ALL-UNNAMED --module-path c:\java\javafx\lib --add-modules javafx.controls,javafx.web
```

> 在 Mac 中，如果需要在命令行中频繁切换 JDK 环境，可以使用 jenv 工具。  
> 使用方法推荐看文章：https://www.wulicode.com/java/tech/jenv.html

参考文章：

-   https://www.b4x.com/android/forum/threads/running-jar-with-double-click-in-java-openjdk-11.140605/
-   https://answers.microsoft.com/en-us/windows/forum/all/jar-files-only-executable-trough-cmd-terminal-java/47b4bd5d-c835-490a-ad2d-34cb745ccc2e
