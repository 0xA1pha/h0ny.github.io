---
layout: post
title: Multi-Release JARs (MRJARs) 多 Java 环境适配
category: Java
tags: [java, MRJARs]
---

> Java 9 的新特性 [JEP 238: Multi-Release JAR Files](https://openjdk.org/jeps/238) 允许为适配不同 Java 版本的环境，给同一个类或方法编写不同版本的代码，以供不同运行时使用。

例如，在项目中为 Java 8（默认）与 Java 17 配置并编写了两种代码。当在 >= Java 17 的环境中运行时，就会默认执行 Java 17 的代码。

---

Multi-Release JAR Files 首先需要在 MANIFEST.MF 中声名：

```
Multi-Release: true
```

并为不同的 Java 版本，提供不同的代码，目录结构如下：

```bash
hony@macbook project % tree
.
├── META-INF
│   └── MANIFEST.MF
├── pom.xml
└── src
    └── main
        ├── java
        │   └── com
        │       └── github
        │           └── h0ny
        │               ├── Main.java
        │               └── Utils.java
        ├── java17
        │   └── com
        │       └── github
        │           └── h0ny
        │               └── Utils.java
        └── resources

```

Maven 适配多个版本 Java 环境配置：

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <version>3.13.0</version>
    <configuration>
        <release>8</release>
        <source>8</source>
        <target>8</target>
    </configuration>
    <executions>
        <!-- Default execution for Java 8 -->
        <execution>
            <id>default-compile</id>
            <goals>
                <goal>compile</goal>
            </goals>
        </execution>
        <!-- Additional execution for Java 17 -->
        <execution>
            <id>compile-java-17</id>
            <phase>compile</phase>
            <goals>
                <goal>compile</goal>
            </goals>
            <configuration>
                <release>17</release>
                <compileSourceRoots>
                    <compileSourceRoot>${project.basedir}/src/main/java17</compileSourceRoot>
                </compileSourceRoots>
                <multiReleaseOutput>true</multiReleaseOutput>
                <!-- <outputDirectory>${project.build.outputDirectory}/META-INF/versions/17</outputDirectory> -->
            </configuration>
        </execution>
    </executions>
</plugin>

<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-jar-plugin</artifactId>
    <version>3.4.2</version>
    <configuration>
        <archive>
            <manifestEntries>
                <Multi-Release>true</Multi-Release>
                <Main-Class>com.github.h0ny.Main</Main-Class>
            </manifestEntries>
        </archive>
    </configuration>
</plugin>
```

检查并运行，查看效果：

```bash
hony@macbook project % jenv shell 1.8
hony@macbook project % mvn package
...

hony@macbook project % jar --list --file target/project-1.0-SNAPSHOT.jar
hony@macbook project % jar -xf target/project-1.0-SNAPSHOT META-INF/MANIFEST.MF && cat META-INF/MANIFEST.MF
...

hony@macbook project % java -jar target/project-1.0-SNAPSHOT.jar
JDK 8 编译

hony@macbook project % jenv shell 22
hony@macbook project % java -jar target/project-1.0-SNAPSHOT.jar
JDK 17 编译

```

参考文章：

-   https://blog.gradle.org/mrjars
-   https://www.baeldung.com/maven-multi-release-jars
-   https://maven.apache.org/plugins/maven-compiler-plugin/multirelease.html
