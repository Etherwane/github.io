---
layout: post
title: HTTP/HTTPS协议详解
date: 2026-03-14
categories: 学习笔记
tags: [HTTP, HTTPS, 协议分析]
---

# HTTP/HTTPS协议详解

## 学习时间
2026年3月14日

## 学习内容
今天系统学习了HTTP/HTTPS协议的工作原理，深入理解了请求头、响应头、状态码的含义，并进行了Wireshark抓包分析和Burp Suite抓包实战。

---

## 一、HTTP协议概述

### 1.1 什么是HTTP？

HTTP（HyperText Transfer Protocol，超文本传输协议）是应用层协议，用于在客户端和服务器之间传输超媒体文档（如HTML、CSS、JavaScript、图片等）。

### 1.2 HTTP的特点

| 特性 | 说明 | 网安关注点 |
|------|------|-----------|
| **无状态** | 服务器不会保存客户端的任何状态信息 | Session Hijacking（会话劫持） |
| **无连接** | 每次请求都是独立的，服务器处理完请求后就断开连接 | 连接劫持、中间人攻击 |
| **基于请求/响应模型** | 客户端发起请求，服务器返回响应 | 请求伪造、响应篡改 |
| **简单快速** | 协议简单，客户端和服务器交互容易 | 协议漏洞利用 |
| **灵活** | 可以传输任意类型的数据（通过Content-Type指定） | 文件上传漏洞 |

### 1.3 HTTP的版本演进

| 版本 | 发布时间 | 主要特性 | 网安关注点 |
|------|---------|---------|-----------|
| **HTTP/0.9** | 1991年 | 仅支持GET请求，只能传输HTML | 极度不安全，明文传输 |
| **HTTP/1.0** | 1996年 | 支持GET、POST、HEAD，支持多种数据类型 | 明文传输、无身份验证 |
| **HTTP/1.1** | 1997年 | 支持持久连接、管道化、分块传输编码 | Host头攻击、HTTP Splitting |
| **HTTP/2.0** | 2015年 | 二进制协议、多路复用、头部压缩 | HPACK攻击、请求伪造 |
| **HTTP/3.0** | 2022年 | 基于QUIC协议，解决队头阻塞 | UDP层面的安全风险 |

### 1.4 HTTP vs HTTPS

| 特性 | HTTP | HTTPS |
|------|------|-------|
| 协议 | 应用层协议 | HTTP + SSL/TLS加密 |
| 端口 | 80 | 443 |
| 数据传输 | 明文传输 | 加密传输 |
| 证书 | 不需要 | 需要SSL/TLS证书 |
| 性能 | 较快 | 较慢（握手和加密开销） |
| 安全性 | 低（易被监听、篡改） | 高（防监听、防篡改） |
| SEO权重 | 较低 | 较高（搜索引擎优先） |

---

## 二、HTTP请求

### 2.1 HTTP请求结构

```plaintxt
请求行（Request Line）
┌─────────────────────────────────────┐
│ Method URI HTTP-Version │
└─────────────────────────────────────┘
请求头（Request Headers）
┌─────────────────────────────────────┐
│ Header-Name: Header-Value │
│ Header-Name: Header-Value │
└─────────────────────────────────────┘
空行
┌─────────────────────────────────────┐
│ │
└─────────────────────────────────────┘
请求体（Request Body）
┌─────────────────────────────────────┐
│ request-body-content │
└─────────────────────────────────────┘
```

### 2.2 HTTP请求方法

| 方法 | 说明 | 幂等性 | 安全性 | 网安关注点 |
|------|------|--------|--------|-----------|
| **GET** | 获取资源 | 是 | 是 | 信息泄露、参数污染 |
| **POST** | 提交数据 | 否 | 否 | SQL注入、XSS、CSRF |
| **PUT** | 更新资源（完整更新） | 是 | 否 | 权限绕过、文件上传 |
| **DELETE** | 删除资源 | 是 | 否 | 权限绕过、拒绝服务 |
| **HEAD** | 获取响应头（不返回响应体） | 是 | 是 | 信息泄露 |
| **OPTIONS** | 获取服务器支持的方法 | 是 | 是 | CORS跨域漏洞 |
| **PATCH** | 更新资源（部分更新） | 否 | 否 | 权限绕过 |
| **CONNECT** | 建立隧道（通常用于HTTPS代理） | 否 | 否 | 代理隧道滥用 |

**幂等性：**  同一个操作执行一次和多次，效果相同。GET、HEAD、PUT、DELETE是幂等的，POST、PATCH不是。

**安全性：**  操作不会改变服务器状态。GET、HEAD、OPTIONS是安全的，POST、PUT、DELETE、PATCH不是。

### 2.3 HTTP请求头详解

#### 基础请求头

| 请求头 | 说明 | 示例 | 网安关注点 |
|--------|------|------|-----------|
| **Host** | 指定请求的主机和端口号 | Host: www.example.com | Host头攻击、虚拟主机遍历 |
| **User-Agent** | 客户端信息（浏览器、操作系统等） | User-Agent: Mozilla/5.0 | User-Agent伪造、指纹识别 |
| **Accept** | 客户端能接受的内容类型 | Accept: text/html,application/json | 内容协商攻击 |
| **Accept-Language** | 客户端能接受的语言 | Accept-Language: zh-CN,zh | 内容协商攻击 |
| **Accept-Encoding** | 客户端能接受的编码方式 | Accept-Encoding: gzip, deflate | 压缩炸弹 |
| **Connection** | 连接管理方式 | Connection: keep-alive | 连接劫持 |
| **Referer** | 请求的来源地址 | Referer: https://www.google.com | 信息泄露、Referer伪造 |

#### 缓存相关请求头

| 请求头 | 说明 | 示例 | 网安关注点 |
|--------|------|------|-----------|
| **If-Modified-Since** | 指定最后修改时间 | If-Modified-Since: Wed, 21 Oct 2025 07:28:00 GMT | 缓存投毒 |
| **If-None-Match** | 指定ETag值 | If-None-Match: "33a64df551425fcc55e4d42a148795d9f25f89d4" | 缓存投毒 |
| **Cache-Control** | 缓存控制指令 | Cache-Control: no-cache | 缓存投毒 |

#### 身份认证请求头

| 请求头 | 说明 | 示例 | 网安关注点 |
|--------|------|------|-----------|
| **Authorization** | 身份认证信息 | Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l | Base64编码泄露、弱密码 |
| **Cookie** | 会话标识 | Cookie: JSESSIONID=123456; token=abcdef | 会话劫持、XSS窃取Cookie |
| **Set-Cookie** | 服务器设置Cookie（响应头） | Set-Cookie: sessionid=123456; HttpOnly; Secure | Cookie篡改、会话固定 |

#### 代理相关请求头

| 请求头 | 说明 | 示例 | 网安关注点 |
|--------|------|------|-----------|
| **Proxy-Authorization** | 代理服务器认证 | Proxy-Authorization: Basic dXNlcjpwYXNz | 弱认证、代理滥用 |
| **X-Forwarded-For** | 请求的原始IP地址 | X-Forwarded-For: 192.168.1.100 | IP伪造、绕过IP限制 |

#### 其他常见请求头

| 请求头 | 说明 | 示例 | 网安关注点 |
|--------|------|------|-----------|
| **Content-Type** | 请求体的内容类型 | Content-Type: application/x-www-form-urlencoded | SQL注入、文件上传 |
| **Content-Length** | 请求体的长度 | Content-Length: 1024 | 长度溢出攻击 |
| **Origin** | 请求的源地址 | Origin: https://www.example.com | CORS漏洞 |
| **Upgrade-Insecure-Requests** | 升级到HTTPS | Upgrade-Insecure-Requests: 1 | 中间人攻击 |

### 2.4 HTTP请求体

#### application/x-www-form-urlencoded

username=admin&password=123456&submit=Login

**网安关注点：**  SQL注入、XSS攻击

#### application/json
```json
{
  "username": "admin",
  "password": "123456"
}
```
```plaintxt

网安关注点： JSON注入、API漏洞
multipart/form-data
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: application/octet-stream

<?php echo "Hello World"; ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
网安关注点： 文件上传漏洞、绕过限制
```
## 三、HTTP响应
### 3.1 HTTP响应结构
```plaintxt
状态行（Status Line）
┌─────────────────────────────────────┐
│ HTTP-Version  Status-Code  Reason-Phrase│
└─────────────────────────────────────┘
响应头（Response Headers）
┌─────────────────────────────────────┐
│ Header-Name: Header-Value         │
│ Header-Name: Header-Value         │
└─────────────────────────────────────┘
空行
┌─────────────────────────────────────┐
│                                   │
└─────────────────────────────────────┘
响应体（Response Body）
┌─────────────────────────────────────┐
│ response-body-content             │
└─────────────────────────────────────┘
```
### 3.2 HTTP状态码详解
#### 1xx（信息性响应）

|状态码	|说明	|网安关注点|
|-------|-----|----------|
|100 Continue	|服务器已收到请求头，客户端应继续发送请求体	|请求体攻击、中间人攻击|

#### 2xx（成功）

|状态码	|说明	|网安关注点|
|-------|-----|----------|
|200 OK|	请求成功	|敏感信息泄露|
|201 Created|	请求成功，创建了新资源|	信息泄露|
|202 Accepted|	请求已接受，但处理未完成|	拒绝服务|
|204 No Content	|请求成功，但无返回内容	|隐藏信息|

#### 3xx（重定向）

|状态码	|说明	|网安关注点|
|-------|-----|----------|
|301 Moved Permanently|	永久重定向|	重定向劫持、钓鱼网站|
|302 Found|	临时重定向	|重定向劫持、开放重定向|
|304 Not Modified|	资源未修改，使用缓存|	缓存投毒|
|307 Temporary Redirect|	临时重定向（保持请求方法）|	重定向劫持|
|308 Permanent Redirect|	永久重定向（保持请求方法）|	重定向劫持|

#### 4xx（客户端错误）

|状态码	|说明	|网安关注点|
|-------|-----|----------|
|400 Bad Request|	请求语法错误|	错误处理漏洞|
|401 Unauthorized|未授权，需要身份认证|	弱认证、绕过认证|
|403 Forbidden|	禁止访问|	权限绕过、目录遍历|
|404 Not Found|	资源不存在|	信息泄露（路径枚举）|
|405 Method Not Allowed|	不允许的请求方法|	方法绕过|
|407 Proxy Authentication Required|	需要代理认证|	弱认证、代理滥用|
|408 Request Timeout|	请求超时|	拒绝服务|
|429 Too Many Requests|	请求过多|	拒绝服务、暴力破解防护|

#### 5xx（服务器错误）

|状态码	|说明	|网安关注点|
|-------|-----|----------|
|500 Internal Server Error|	服务器内部错误|	信息泄露（错误信息）|
|501 Not Implemented|	服务器不支持请求方法|	信息泄露|
|502 Bad Gateway|	网关或代理服务器错误|	拒绝服务|
|503 Service Unavailable|	服务不可用|	拒绝服务|
|504 Gateway Timeout|	网关超时|	拒绝服务|

### 3.3 HTTP响应头详解
#### 基础响应头

|响应头|	说明|	示例|	网安关注点|
|-----|-----|-----|------------|
|Server	|服务器信息（软件版本）|	Server: Apache/2.4.41 (Ubuntu)|	服务器信息泄露|
|Date	|响应时间|	Date: Fri, 14 Mar 2026 01:40:39 GMT|	时间同步攻击|
|Content-Type	|响应体的内容类型|	Content-Type: text/html; charset=utf-8|	MIME类型混淆|
|Content-Length	|响应体的长度|	Content-Length: 1234|	长度溢出|
|Content-Encoding	|响应体的编码方式|	Content-Encoding: gzip|	压缩炸弹|

#### 缓存相关响应头

|响应头|	说明|	示例|	网安关注点|
|-----|-----|-----|------------|
|Cache-Control|	缓存控制指令|	Cache-Control: no-cache, no-store|	缓存投毒|
|Expires|	缓存过期时间|	Expires: Fri, 14 Mar 2026 02:00:00 GMT|	缓存投毒|
|ETag|	资源的版本标识|	ETag: "33a64df551425fcc"|	缓存投毒|
|Last-Modified|	资源的最后修改时间|	Last-Modified: Wed, 21 Oct 2025 07:28:00 GMT|	缓存投毒|

#### 安全相关响应头

|响应头|	说明|	示例|	网安关注点|
|-----|-----|-----|------------|
|Set-Cookie|	设置Cookie|	Set-Cookie: sessionid=123456; HttpOnly; Secure; SameSite=Strict|	会话劫持、XSS|
|Strict-Transport-Security|	强制使用HTTPS|	Strict-Transport-Security: max-age=31536000; includeSubDomains|	中间人攻击|
|Content-Security-Policy|	内容安全策略|	Content-Security-Policy: default-src 'self'|	XSS防御|
|X-Frame-Options|	防止点击劫持|	X-Frame-Options: DENY|	点击劫持|
|X-XSS-Protection|	XSS保护|	X-XSS-Protection: 1; mode=block|	XSS|
|X-Content-Type-Options|	防止MIME类型混淆|	X-Content-Type-Options: nosniff|	MIME类型混淆|
|Access-Control-Allow-Origin|	CORS跨域控制|	Access-Control-Allow-Origin: https://www.example.com|	CORS漏洞|
|Referrer-Policy|	Referer策略|	Referrer-Policy: no-referrer|	信息泄露|
|Permissions-Policy|	功能权限策略|	Permissions-Policy: geolocation=()|	权限泄露|

#### 其他常见响应头

|响应头|	说明|	示例|	网安关注点|
|-----|-----|-----|------------|
|Location|	重定向地址|	Location: https://www.example.com/new-page|	重定向劫持|
|Set-Cookie|	设置Cookie|	Set-Cookie: sessionid=123456; HttpOnly; Secure|	会话劫持|
|WWW-Authenticate|	身份认证方式|	WWW-Authenticate: Basic realm="Restricted Area"|	弱认证|

## 四、HTTPS协议详解
### 4.1 什么是HTTPS？

HTTPS（Hypertext Transfer Protocol Secure）是HTTP的安全版本，通过SSL/TLS协议对HTTP通信进行加密，防止数据被窃听、篡改、伪造。

### 4.2 HTTPS的工作原理
```plaintxt
HTTPS连接建立过程
客户端                            服务端
   │                                  │
   │  ① ClientHello                   │
   │────────────────────────────────> │
   │   (支持的TLS版本、加密套件、随机数1) │
   │                                  │
   │  ② ServerHello + ServerHelloDone  │
   │<────────────────────────────────│
   │   (选择TLS版本和加密套件、随机数2、证书) │
   │                                  │
   │  ③ 验证证书                      │
   │   [客户端验证服务器证书]         │
   │                                  │
   │  ④ 生成会话密钥                  │
   │   [使用随机数1、随机数2、随机数3]│
   │                                  │
   │  ⑤ ClientKeyExchange             │
   │────────────────────────────────> │
   │   (加密的预主密钥)                │
   │                                  │
   │  ⑥ ChangeCipherSpec + Finished   │
   │<────────────────────────────────│
   │   (切换到加密通道、握手完成)      │
   │                                  │
   │  ⑦ ChangeCipherSpec + Finished   │
   │────────────────────────────────> │
   │   (切换到加密通道、握手完成)      │
   │                                  │
   │         HTTPS通信开始             │
```

### HTTPS加密过程详解
**1.客户端发送ClientHello**

支持的TLS版本（TLS 1.2、TLS 1.3）

支持的加密套件（如TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384）

客户端随机数（Client Random）

**2.服务端发送ServerHello + ServerHelloDone**

选择的TLS版本和加密套件

服务端随机数（Server Random）

服务器证书（包含公钥）

可选：请求客户端证书

**3.客户端验证服务器证书**

验证证书是否过期

验证证书是否被吊销

验证证书链是否可信

验证证书的域名是否匹配

**4.客户端生成会话密钥**

客户端生成预主密钥（Pre-Master Secret）

使用服务端公钥加密预主密钥

使用Client Random、Server Random、Pre-Master Secret生成会话密钥

**5.客户端发送ClientKeyExchange**

加密的预主密钥

**6.双方切换到加密通道**

双方发送ChangeCipherSpec消息

双方发送Finished消息（使用会话密钥加密）

握手完成，开始加密通信

### 4.3 SSL/TLS证书
```plaintxt
┌─────────────────────────────────────┐
│ 版本号                             │
├─────────────────────────────────────┤
│ 序列号                             │
├─────────────────────────────────────┤
│ 签名算法                           │
├─────────────────────────────────────┤
│ 颁发者（Issuer）                  │
├─────────────────────────────────────┤
│ 有效期                             │
├─────────────────────────────────────┤
│ 主体（Subject）                    │
│   - 通用名称（CN）                 │
│   - 组织（O）                      │
│   - 组织单位（OU）                 │
│   - 国家（C）                      │
├─────────────────────────────────────┤
│ 主体公钥信息                       │
├─────────────────────────────────────┤
│ 扩展字段                           │
│   - 主题备用名称（SAN）            │
│   - 密钥用途                       │
│   - 基本约束                       │
├─────────────────────────────────────┤
│ 颁发者签名                         │
└─────────────────────────────────────┘
```
#### 证书类型
|类型|	说明|	适用场景|
|----|------|---------|
|DV证书（Domain Validation）|	仅验证域名所有权|	个人博客、测试网站|
|OV证书（Organization Validation）|	验证域名和组织|	企业官网|
|EV证书（Extended Validation）|	严格验证|	金融机构、电商|

#### 证书验证流程
**1.验证证书有效期**

检查notBefore和notAfter字段

确保证书未过期

**2.验证证书链**

验证证书是否由可信CA颁发

验证证书链的完整性

**3.验证证书吊销状态**

CRL（证书吊销列表）

OCSP（在线证书状态协议）

**4.验证证书域名**

验证CN字段或SAN字段

确保域名匹配

**5.验证证书签名**

使用CA的公钥验证签名

确保证书未被篡改

### 4.4 HTTPS安全威胁
|威胁类型|	原理|	防御措施|
|-------|-----|---------|
|中间人攻击|	攻击者拦截并篡改通信|	HSTS、证书固定|
|SSL剥离攻击|	强制降级到HTTP|	HSTS|
|证书伪造|	攻击者伪造服务器证书|	证书验证、CRL/OCSP|
|证书过期|	证书未及时更新|	自动续期、监控|
|弱加密套件|	使用过时的加密算法|	禁用弱加密套件|
|心脏滴血漏洞|	OpenSSL缓冲区溢出|	更新OpenSSL|
|POODLE攻击|	SSL 3.0协议漏洞|	禁用SSL 3.0|
|BEAST攻击|	CBC模式漏洞|	使用GCM模式|

## 五、HTTP/HTTPS安全攻击与防御
### 5.1 常见攻击类型

#### SQL注入

原理： 攻击者在HTTP请求中注入恶意SQL代码，导致数据库执行非预期操作。

**攻击示例：**
```plaintxt
正常请求：http://example.com/login?username=admin&password=123456

SQL注入请求：http://example.com/login?username=admin' OR '1'='1&password=123456

SQL语句变为：SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='123456'
结果：绕过密码验证，以admin身份登录
```
**防御措施：**

1.使用参数化查询（PreparedStatement）

2.对用户输入进行严格的过滤和验证

3.使用最小权限原则配置数据库账号

#### XSS跨站脚本攻击

原理： 攻击者在网页中注入恶意脚本，当用户访问时，脚本在用户浏览器中执行。

**攻击示例：**
```plaintxt
存储型XSS：
评论内容：<script>alert('XSS')</script>
反射型XSS：
http://example.com/search?q=<script>alert('XSS')</script>
```

**防御措施：**

1.对用户输入进行HTML实体编码

2.设置Content-Security-Policy响应头

3.对Cookie设置HttpOnly和Secure标志


#### CSRF跨站请求伪造

原理： 攻击者诱导用户在已登录的网站上执行非预期操作。

**攻击示例：**
```plaintxt
用户登录了银行网站，session未过期
用户访问恶意网站：http://evil.com/transfer
恶意页面中：<img src="http://bank.com/transfer?to=hacker&amount=10000">
结果：用户在不知情的情况下，向攻击者转账10000元
```
**防御措施：**

1.使用CSRF Token

2.设置SameSite Cookie属性

3.验证Referer头（但可被绕过）

#### 请求走私

原理： 攻击者利用请求头解析差异，走私请求到后端服务器。

**攻击示例：**
```plaintxt
Content-Length: 10

GET /admin HTTP/1.1
Host: example.com

实际请求：GET /admin（绕过前端WAF）
```
**防御措施：**

1.统一请求头解析规则

2.使用严格的HTTP解析器

3.配置正确的Content-Length和Transfer-Encoding

#### Host头攻击

原理： 攻击者篡改Host头，导致缓存投毒或绕过安全控制。

**攻击示例：**
```plaintxt
正常请求：Host: example.com
攻击请求：Host: evil.com
结果：恶意网站缓存投毒，用户访问example.com时被重定向到evil.com
```
**防御措施：**

1.验证Host头

2.使用白名单验证Host值

3.在反向代理中配置正确的Host

#### HTTP请求走私

原理： 攻击者利用Content-Length和Transfer-Encoding的解析差异，走私请求。

**攻击示例：**
```plaintxt
Content-Length: 8
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: example.com

实际请求：走私到后端服务器的/admin请求
```
**防御措施：**

1.统一HTTP解析规则

2.禁用Transfer-Encoding（如果不需要）

3.使用严格的HTTP解析器

### 5.2 安全响应头配置

#### 必须配置的安全响应头

|响应头|	推荐值|	作用|
|------|------|------|
|Strict-Transport-Security|	max-age=31536000; includeSubDomains; preload|	强制使用HTTPS|
|Content-Security-Policy|	default-src 'self'; script-src 'self' 'unsafe-inline'|	防止XSS|
|X-Frame-Options|	DENY|	防止点击劫持|
|X-Content-Type-Options|	nosniff|	防止MIME类型混淆|
|X-XSS-Protection|	1; mode=block|	XSS保护|
|Referrer-Policy|	strict-origin-when-cross-origin|	防止信息泄露|
|Permissions-Policy|	geolocation=(), camera=(), microphone=()|	功能权限控制|

#### Cookie安全配置

|属性|	说明|	推荐值|
|----|------|------|
|HttpOnly|	防止JavaScript访问Cookie|	设置HttpOnly|
|Secure|	仅通过HTTPS传输Cookie|	设置Secure|
|SameSite|	防止CSRF攻击|	SameSite=Strict或Lax|

## 六、Wireshark抓包实战
### 6.1 抓取HTTP请求

**步骤：**

1.打开Wireshark，选择网卡

2.在过滤器中输入：http.request.method == "GET"

3.访问一个网站

4.停止抓包，分析数据包

**预期结果：**
```plaintxt
No. Time        Source           Destination      Protocol         Info
1   0.000000    192.168.1.100    93.184.216.34    HTTP              GET / HTTP/1.1
```
**分析方法：**

1.双击数据包，查看详细信息

2.展开"Hypertext Transfer Protocol"字段

3.查看请求行、请求头、请求体

### 6.2 抓取HTTP响应

**步骤：**

1.在Wireshark过滤器中输入：http.response.code == 200

2.访问一个网站

3.停止抓包，分析数据包

**预期结果：**
```plaintxt
No. Time        Source          Destination     Protocol    Info
1   0.000000    93.184.216.34   192.168.1.100   HTTP        HTTP/1.1 200 OK
```
**分析方法：**
1.双击数据包，查看详细信息

2.展开"Hypertext Transfer Protocol"字段

3.查看状态行、响应头、响应体

### 6.3 抓取HTTPS握手

**步骤：**

1.在Wireshark过滤器中输入：ssl.handshake.type == 1

2.访问一个HTTPS网站

3.停止抓包，分析数据包

**预期结果：**
```plaintxt
No. Time        Source          Destination     Protocol   Info
1   0.000000    192.168.1.100   93.184.216.34   TLSv1.3    Client Hello
2   0.001234    93.184.216.34   192.168.1.100   TLSv1.3    Server Hello
3   0.002567    93.184.216.34   192.168.1.100   TLSv1.3    Certificate
4   0.003890    93.184.216.34   192.168.1.100   TLSv1.3    Server Hello Done
5   0.005123    192.168.1.100   93.184.216.34   TLSv1.3    Client Key Exchange
6   0.006456    192.168.1.100   93.184.216.34   TLSv1.3    Change Cipher Spec
7   0.007789    192.168.1.100   93.184.216.34   TLSv1.3    Finished
8   0.009012    93.184.216.34   192.168.1.100   TLSv1.3    Change Cipher Spec
9   0.010345    93.184.216.34   192.168.1.100   TLSv1.3    Finished
```
**分析方法：**

1.双击ClientHello数据包

2.查看"Client Hello"字段中的支持的TLS版本和加密套件

3,双击Certificate数据包

4.查看证书的详细信息（颁发者、有效期、公钥）

## 七、Burp Suite抓包实战
### 7.1 拦截HTTP请求

**步骤：**

1.打开Burp Suite

2.在Proxy标签中，设置浏览器代理为127.0.0.1:8080

3.开启Intercept（拦截）

4.浏览器访问网站

5.查看被拦截的请求

**分析方法：**

1.查看请求行（Method、URI、HTTP版本）

2.查看请求头（Host、User-Agent、Cookie等）

3.查看请求体（POST参数）

4.修改请求参数，Forward（转发）或Drop（丢弃）

### 7.2 拦截HTTP响应

**步骤：**

1.在Burp Suite的Proxy标签中，选择"Response is Interception"

2.浏览器访问网站

3.查看被拦截的响应

**分析方法：**

1.查看状态行（状态码、原因短语）

2.查看响应头（Server、Set-Cookie、Content-Type等）

3.查看响应体（HTML内容、JSON数据）

### 7.3 修改请求参数测试漏洞

#### SQL注入测试：
```plaintxt
原始请求：username=admin&password=123456
修改请求：username=admin' OR '1'='1&password=123456
Forward请求，观察响应
```
#### XSS测试：
```plaintxt
原始请求：search=hello
修改请求：search=<script>alert(1)</script>
Forward请求，观察响应
```
## 八、学习收获

### ✅ 已掌握

HTTP协议的结构和特点

HTTP请求方法和请求头详解

HTTP响应状态码和响应头详解

HTTPS的工作原理和加密过程

SSL/TLS证书的验证流程

常见Web攻击原理（SQL注入、XSS、CSRF）

安全响应头的配置方法

使用Wireshark抓包分析HTTP/HTTPS

使用Burp Suite拦截和修改请求

### 🔄 待深入

HTTP/2和HTTP/3的新特性

请求走私的高级利用技巧

CSP策略的详细配置

TLS 1.3的改进点

更多Web攻击类型（SSRF、XXE等）

## 九、待解决的问题
### ⏳ 疑问1：为什么POST请求不安全，而GET请求安全？

初步理解： GET不修改服务器状态，POST会修改，但GET也能被攻击（如信息泄露）

需要进一步： 理解幂等性和安全性的严格定义

### ⏳ 疑问2：如何防止请求走私攻击？

初步理解： 统一HTTP解析规则，禁用Transfer-Encoding

需要进一步： 实际测试不同Web服务器的解析差异

### ⏳ 疑问3：CSP策略如何配置才能防止所有XSS？

初步理解： default-src 'self'，script-src 'self' 'nonce-...'

需要进一步： 理解CSP的各个指令和配置方法

## 十、参考资料
### 📚 书籍

《HTTP权威指南》

《Web安全深度剖析》

《Burp Suite实战指南》

### 🌐 在线资源

MDN Web Docs - HTTP（https://developer.mozilla.org/zh-CN/docs/Web/HTTP）

OWASP Top 10（https://owasp.org/www-project-top-ten/）

Mozilla Observatory（https://developer.mozilla.org/en-US/observatory）

### 🎬 视频教程

B站：《Web安全入门》

Coursera：《Web Security》

## 十一、总结
### 核心要点（背诵版）

**HTTP请求方法：**

**GET：** 获取资源（安全、幂等）

**POST：** 提交数据（不安全、非幂等）

**PUT：** 更新资源（不安全、幂等）

**DELETE：** 删除资源（不安全、幂等）

**HTTP状态码：**

**2xx：** 成功（200、201、204）

**3xx：** 重定向（301、302、304）

**4xx：** 客户端错误（400、401、403、404）

**5xx：** 服务器错误（500、502、503）

**HTTPS加密过程：**

1.ClientHello（发送支持的TLS版本和加密套件）

2.ServerHello + Certificate（发送证书）

3.验证证书

4.生成会话密钥

5.ClientKeyExchange（加密预主密钥）

6.双方切换到加密通道

**安全响应头：**

**HSTS：** 强制HTTPS

**CSP：** 防止XSS

**X-Frame-Options：** 防止点击劫持

**Secure + HttpOnly Cookie：** 防会话劫持

## 持续学习，持续分享！
```plaintxt
"HTTP/HTTPS是Web通信的基础，深入理解协议原理才能有效发现和防御Web漏洞。"
```
