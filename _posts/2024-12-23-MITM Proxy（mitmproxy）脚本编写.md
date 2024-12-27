---
layout: post
title: MITM Proxy（mitmproxy）编写流量解密脚本
category: APP
tags: [mitmproxy]
---

Python 脚本编写示例：

```python
from mitmproxy import http
from mitmproxy import ctx

# 对加密的请求体进行解密处理
def request(flow: http.HTTPFlow) -> None:
    # 添加日志输出以验证
    if "example.com" in flow.request.host:
        flow.request.headers["X-Forwarded-For"] = "Modified-by-mitmproxy"
        flow.request.headers["X-Modified-By"] = "mitmproxy"
        # 打印日志
        ctx.log.info("Request modified: Added header X-Modified-By")

# 对加密的响应体进行解密处理
def response(flow: http.HTTPFlow) -> None:
    if "example.com" in flow.request.host:
        flow.response.headers["X-Processed-By"] = "mitmproxy"
        # 打印响应日志
        ctx.log.info("Response intercepted: %s" % flow.response.text[:100])  # 只显示前100字符

```

命令行，运行 mitm 使用脚本示例：

```bash
# mitmdump/mitmproxy/mitmweb
mitmweb --mode upstream:http://127.0.0.1:8888 -w output.mitm -s modify_flow.py
```

## mitm + burp 流量解密案例

加密流量如下图，只有请求包有加密：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/23761f4c339916d6.png)

但数据包有两种请求格式，只能根据 HTTP 请求头的 Content-Type 进行判断：

-   `{ "params":"xxx" }`
-   `params=xxx`

---

开启两个 mitm 监听端口，一个位于第一个监听器，将请求包的流量进行解密，传输给 burp 进行修改。

在 burp 中配置上游代理（Upstream proxy servers），将修改后的流量传入第二个 mitm 监听端口，将请求包的流量进行加密后，传输给服务器。

流程图如下：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/f27acf490d7fe1ae.png)

启动 mitm 命令：

```bash
# mitm 解密 --> burp
mitmweb --ssl-insecure --mode upstream:http://127.0.0.1:8888 --set http2=false --web-port 8081 -p 8080 -s mitm_decrypt.py

# burp --> mitm 加密
mitmweb --ssl-insecure --set http2=false --web-port 8082 -p 9999 -s mitm_encrypt.py
```

解密脚本 mitm_decrypt.py 示例：

```python
import json

from mitmproxy import http
from mitmproxy import ctx


def request(flow: http.HTTPFlow) -> None:
    # 用于调试，flow.request.host 可能为 ip 而非域名
    ctx.log.info(f"Flow request host: {flow.request.host}")
    # 拦截请求并转发给 Burp
    if flow.request.host == "127.0.0.1":
        flow.request.host = "example.com"
    if "example.com" in flow.request.host:
        flow.request.headers["X-Forwarded-For"] = "Modified-by-mitmproxy"

        if flow.request.headers.get("Content-Type", "").startswith("application/json"):
            try:
                # 解析请求体为 JSON
                request_data = json.loads(flow.request.content)
                # 提取 "params" 字段
                params_value = request_data.get("params", None)
                if params_value:
                    # 打印和处理 params 的值
                    ctx.log.info(f"Extracted params (json): {params_value}")
                    processed_value = decrypt_params_value(params_value)
                    if processed_value:
                        ctx.log.info(f"Decrypted params (json): {processed_value}")
                        flow.request.text = processed_value
            except json.JSONDecodeError:
                ctx.log.info("Failed to parse JSON from request body")

        elif "params=" in flow.request.text:
            # 提取 params=xxx 值
            start_idx = flow.request.text.find("params=") + len("params=")
            encoded_params = flow.request.text[start_idx:].split("&")[0]  # 假设只有一个 params，或用 "&" 分割多个参数
            ctx.log.info(f"Extracted params (key=value): {encoded_params}")
            processed_value = decrypt_params_value(encoded_params)
            if processed_value:
                ctx.log.info(f"Decrypted params (key=value): {processed_value}")
                flow.request.text = processed_value



import binascii
import urllib.parse

# 解密 params_value
# 解密处理：HEX 解码 -> XOR 解密 ->  URL Encode
def decrypt_params_value(params_value):
    try:
        # 第一步：HEX 解码
        hex_decoded = binascii.unhexlify(params_value)  # 如果 params_value 非法 hex，会抛出异常

        # 第二步：XOR 解密
        xor_key = 11  # Key 为 11
        xor_decrypted = bytes([byte ^ xor_key for byte in hex_decoded])  # 解密后的数据

        # 第三步：URL Decode
        url_decoded = urllib.parse.unquote(xor_decrypted.decode('utf-8'))  # 解码为字符串

        return url_decoded
    except Exception as e:
        print(f"Error decrypt: {e}")
        return None

```

加密脚本 mitm_encrypt.py 示例：

```python
import json

from mitmproxy import http
from mitmproxy import ctx


def request(flow: http.HTTPFlow) -> None:
    # 处理从 Burp 返回的请求包流量
    #  if "crm.11185.cn" in flow.request.host:
    if "example.com" in flow.request.host:
        flow.request.headers["X-Processed-By"] = "mitmproxy"
        # 打印经过 Burp 修改后的请求体
        modified_request_data = flow.request.text
        ctx.log.info(f"Modified by Burp request body: {modified_request_data[:100]}")
        if flow.request.headers.get("Content-Type", "").startswith("application/json"):

            # 反向处理生成新的 params_value
            params_value = encrypt_params_value(modified_request_data)
            if params_value:
                # 替换 request 数据中的 params 字段
                request_data = {
                    "params": params_value
                }
                flow.request.text = json.dumps(request_data)
                ctx.log.info(f"Encrypted params (json): {flow.request.text}")

        elif flow.request.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            params_value = encrypt_params_value(modified_request_data)
            if params_value:
                flow.request.text = "params=" + params_value
                ctx.log.info(f"Encrypted params (key=value): {flow.request.text}")


import binascii
import urllib.parse


# 反向处理 params_value
# 反向处理：URL Encode -> XOR 加密 -> HEX 编码
def encrypt_params_value(original_value):
    try:
        # **第一步**：URL Encode（确保 consistent with URL Decode）
        # 注：不对 JSON 数据中分割的 : 和 , 进行 URL 编码。
        # url_encoded = urllib.parse.quote(original_value.encode("utf-8"), safe=':,')
        url_encoded = urllib.parse.quote(original_value.encode("utf-8"))

        # **第二步**：XOR 加密 (Key 为 11，与解密对应)
        xor_key = 11
        xor_encrypted = bytes([ord(char) ^ xor_key for char in url_encoded])  # 转字符到字节异或

        # **第三步**：HEX 编码（确保一致于解密的 Hex Decode）
        hex_encoded = binascii.hexlify(xor_encrypted).decode("utf-8")  # 转 HEX 字符串

        return hex_encoded
    except Exception as e:
        print(f"Error generating params_value: {e}")
        return None

```

burp 上游代理（Upstream proxy servers）配置：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/f5e33608fceb93c7.png)

流量解密后的效果：

![alt text](https://raw.githubusercontent.com/h0ny/repo/main/images/c75984880c32db61.png)
