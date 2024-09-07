---
layout: post
title: Java 代码混淆 - allatori
category: Development
tags: [java, obfuscated]
---

项目结构：

```
.
├── lib
│   ├── allatori-annotations.jar
│   ├── allatori.jar
│   └── allatori.xml
├── pom.xml
└── src
   └── main...
```

配置 maven 以插件的形式加载 allatori.jar 对打包后的项目 jar 包进行混淆处理。

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-resources-plugin</artifactId>
    <version>3.3.0</version>
    <configuration>
        <encoding>UTF-8</encoding>
    </configuration>
    <executions>
        <!-- 执行这个插件的时候执行申明的所有 phase -->
        <execution>
            <id>copy-and-filter-allatori-config</id>
            <phase>package</phase>
            <goals>
                <goal>copy-resources</goal>
            </goals>
            <configuration>
                <!-- 最终 jar 包存放的位置 -->
                <outputDirectory>${basedir}/target</outputDirectory>
                <resources>
                    <resource>
                        <!-- 配置 allatori.jar 和 allatori.xml 所在目录 -->
                        <directory>${basedir}/lib</directory>
                        <includes>
                            <!-- 配置文件文件名 -->
                            <include>allatori.xml</include>
                        </includes>
                        <filtering>true</filtering>
                    </resource>
                </resources>
            </configuration>
        </execution>
    </executions>
</plugin>
```

allatori.xml 配置内容如下：

```xml
<config>
    <input>
        <!-- in 表示传入的原始 jar 包位置，out 表示输出的混淆后的 jar/war 包 -->
        <jar in="../target/jshERP-exploit-1.0.1-jar-with-dependencies.jar"
             out="../target/jshERP-exploit-1.0.1-jar-with-dependencies-obfuscated.jar"/>
    </input>

    <classpath>
        <jar name="/Users/hony/.m2/repository/**/*.jar"/>
    </classpath>

    <keep-names>
        <class access="protected+">
            <field access="protected+"/>
            <method access="protected+"/>
        </class>
    </keep-names>

    <property name="log-file" value="log.xml"/>

    <!-- 忽略的包或类，这些文件将不被混淆 -->
    <ignore-classes>
        <!-- 不要混淆主类 -->
        <class template="class com.hony.Main" />
        <!-- 不要混淆第三方的代码，否则会运行jar包会报错java.lang.NoClassDefFoundError -->
        <!-- <class template="class com.hony.util.JavassistUtils" />-->
        <class template="class com.hony.template.DefinePlugin" />
        <class template="class *starblues*" />
        <class template="class *miglayout*" />
        <class template="class *formdev*" />
        <class template="class *alibaba*" />
        <class template="class *org*" />
        <class template="class *woodpecker*" />
        <class template="class *tomcat*" />
        <class template="class *springframework*" />
        <class template="class *lombok*" />
    </ignore-classes>

    <!-- 到期时间(到期后无法启动jar) 格式：yyyy/mm/dd-->
    <!--<expiry date="2021/04/03" string="SERVICE EXPIRED!"/>-->
    <!-- 随机命名混淆字符-->
    <!--<property name="random-seed" value="abcdef ghnljk svi"/>-->

</config>
```

最后，就可以使用 `mvn package` 打包了。
