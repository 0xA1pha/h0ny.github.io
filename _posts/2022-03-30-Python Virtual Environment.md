---
title: Python Virtual Environment
date: 2022-03-30 14:35:19.257
updated: 2022-09-18 10:15:50.851
categories: [Python]
tags: [python, venv]
---

## Background

Python 虚拟环境的主要目的是为了给不同的工程项目创建相互独立的运行环境。使用虚拟环境可以有效的避免在运行 Python 脚本时，依赖包之间的冲突问题。

从 Python 3.3 开始，标准库中添加了一个用于创建虚拟环境的模块 venv[^1]。也可以选择 Virtualenv[^2]、Pipenv、Poetry、Conda 这类第三方库创建虚拟环境。

## Creating and Using Virtual Environments

创建一个虚拟环境：

```
python3 -m venv /path/to/new/virtual/environment
```

> 注：使用 `--system-site-packages` 参数可让虚拟环境访问系统 site-packages 目录，系统 site-packages 目录下没有包才会需要安装，可减少虚拟环境的大小。

Windows 下的目录结构：

| Type | Name       | Description                                                                                                                         |
| ---- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 目录 | Include    | 使用它来包含可能安装的依赖于 C 扩展的包 C 头文件。                                                                                  |
| 目录 | Lib        | 存放虚拟环境中 pip install 所安装的包。<br />进入虚拟环境后，可使用 pip list 列出虚拟环境中的包。                                   |
| 目录 | Scripts    | 存放虚拟环境中的可执行脚本文件。<br />在该目录下使用 .\\activate 即可激活并进入到虚拟环境中，离开虚拟环境运行 deactivate 命令即可。 |
| 文件 | pyvenv.cfg | Python 虚拟环境的配置文件。                                                                                                         |

使用示例：

```
PS C:\> python3 -m venv env
PS C:\> .\env\Scripts\activate
(env) PS C:\> pip list
Package    Version
---------- -------
pip        23.1.2
setuptools 65.5.0
(env) PS C:\> deactivate
PS C:\>
```

## Save Dependencies Information in Environment

使用 pip freeze[^3] 命令，对项目中虚拟环境的依赖信息进行保存，可以方便别人对项目依赖进行安装。

```
# bash
pip freeze > requirements.txt

# powershell
pip freeze | Out-File -Encoding ASCII requirements.txt
```

> 注：如果该命令不在虚拟环境中使用，会把系统环境中的所有包都导出来。

如果要在系统环境中，直接导出某个项目的依赖信息，需要使用 pipreqs[^4] 库。
pipreqs 库是通过对项目目录进行扫描，自动发现使用了那些类库，生成依赖清单，但可能会有些偏差需要自行检查调整。

```
pipreqs --encoding=utf8 ./
```

保存依赖信息后，其他人只需要使用：

```
pip install -r .\requirements.txt
```

就可以安装该项目所需的所有依赖。

---

## Links & Resources

<!-- Comments -->

[^1]: venv 官方使用文档：[https://docs.python.org/zh-cn/3/library/venv.html](https://docs.python.org/zh-cn/3/library/venv.html)
[^2]: virtualenv 官方使用文档：[https://virtualenv.pypa.io/en/latest/installation.html](https://virtualenv.pypa.io/en/latest/installation.html)
[^3]: pip freeze 官方使用文档：[https://pip.pypa.io/en/stable/cli/pip_freeze/](https://pip.pypa.io/en/stable/cli/pip_freeze/)
[^4]: Avoid Using “pip freeze” — Use “pipreqs” instead：[https://towardsdatascience.com/goodbye-pip-freeze-welcome-pipreqs-258d2e7a5a62](https://towardsdatascience.com/goodbye-pip-freeze-welcome-pipreqs-258d2e7a5a62)
