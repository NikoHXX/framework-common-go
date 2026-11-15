# apiencrypt

接口加解密中间件。引擎上的 `Filter` 对齐 Java `CryptoFilter`：带 `encrypt-key` 就解密请求；`globalRequest` / `globalResponse` 强制加解密；排除路径、multipart、SSE 按规则跳过。路由上的 `APIEncryptWithConfig` 等价于 `@ApiEncrypt`。`!Enabled` 时直通。

对应原 `framework-core/encrypt`，抽出为独立包。

## 用法

`Filter` 挂在引擎上，位置是 `RepeatableBody` 之后、`AccessLog` / `XSS` 之前。路由上的中间件只用来标记 `@ApiEncrypt`：

```go
import (
	"github.com/NikoHXX/framework-common-go/middleware/apiencrypt"
)

cfg := config.Get() // 本模块配置子集

r.Use(repeatablebody.RepeatableBodyWithConfig(cfg.RepeatableBody))
r.Use(apiencrypt.Filter(cfg.APIEncrypt))
r.Use(accesslog.AccessLogWithConfig(cfg.AccessLog))

// 等价于 @ApiEncrypt：全局请求加密关闭时，POST/PUT/PATCH 必须带密钥头
g.POST("/login", sagin.Ignore(),
	apiencrypt.APIEncryptWithConfig(cfg.APIEncrypt), handler.Login)

// 等价于 @ApiEncrypt(response = true)
g.POST("/secret", apiencrypt.APIEncryptWithResponseWithConfig(cfg.APIEncrypt), handler.Secret)
```

没挂标记的接口，只要带了 `encrypt-key` 也会解密。`globalRequest` / `globalResponse` 打开后按全局规则强制加解密，不再看路由标记。`excludeUrls` 整段跳过，`excludeRequestUrls` / `excludeResponseUrls` 只跳过一边。multipart 上传不解密请求，`Accept: text/event-stream` 不加密响应。

> 须挂在 `RepeatableBody` 之后：本中间件解出明文后会覆盖 `gin.BodyBytesKey`，
> 让下游 XSS 清洗、访问日志、防重指纹都取到明文。

## 配置

| 字段                   | 默认值        | 说明                                                                 |
|------------------------|---------------|----------------------------------------------------------------------|
| `enabled`              | `false`       | 是否启用。false 时过滤器和路由标记都直通。                           |
| `globalRequest`        | `false`       | POST/PUT/PATCH 必须带密钥头。开启后忽略路由标记。                    |
| `globalResponse`       | `false`       | 加密 JSON/纯文本响应。开启后忽略路由标记，且必须配置 `publicKey`。   |
| `headerFlag`           | `encrypt-key` | 传递 AES 密钥的请求/响应头名。                                      |
| `publicKey`            | -             | 响应加密用的 RSA 公钥，base64 编码的 X.509 SPKI。                   |
| `privateKey`           | -             | 请求解密用的 RSA 私钥，base64 编码的 PKCS#8。启用时必填。           |
| `excludeUrls`          | 空            | 请求和响应都跳过，Ant 风格。                                         |
| `excludeRequestUrls`   | 空            | 只跳过请求体。multipart 上传另外在代码里跳过。                       |
| `excludeResponseUrls`  | 空            | 只跳过响应。SSE 和二进制响应另外在代码里跳过。                       |

默认值与校验由 `newCrypto`（路由注册期）就地做：`HeaderFlag` 为空补默认头名，`enabled` 为 true 却缺 `privateKey` 直接
panic；密钥解析失败同样 panic，启动期 fail-fast，与原 `encrypt.Init` 一致。调用方无需手动调 `SetDefaults` / `Validate`。

## 协议

1. **请求解密**：前端用 RSA 公钥加密一把随机 AES 密钥放进密钥头，body 用该 AES 密钥加密 （ECB + PKCS#7，base64）。服务端用 RSA
   私钥解出密钥头 → 再 base64 解一次 → AES 解密 body。
2. **响应加密**：服务端随机生成 AES 密钥加密响应体，密钥用 RSA 公钥加密放进密钥头回写。
3. **剥 JSON 引号**：前端 axios 把密文当 JSON body 发会 `JSON.stringify` 一次，上线带引号； Go 标准库 base64 严格解码不跳过引号（与
   hutool 不同），须 `unwrapJSONString` 先剥。

## 行为约定

- **缺密钥头 → 403**：命中加密注解却未携带密钥头，回 `{code:403,msg:"没有访问权限，请联系管理员授权",data:null}`。
- **解密 / 加密失败 → 500**：统一回 `{code:500,msg:"请求解密失败"|"响应加密失败",data:null}`
  （HTTP 200），明细只进日志。不走 `errs` + 全局 `Recover` 兜底，用 `fmt` 直写 JSON 终止链， 免去 `errs` 依赖与「Abort 后等
  Recover 才落响应」的隐式时序。响应码与原 `errs` 路径一致 （原 `errs.New(0, ...)` 经 `Recover` 亦回落 500）。 **本包不引
  `framework-core/model/response`**， 不定义 envelope 类型，按项目统一 `{code,msg,data}` 形态就地拼。
- **密钥头在写出密文前设置**：响应先缓冲，确认正文是 JSON 或纯文本后再写 `encrypt-key`，下载和空响应不带这个头。
- **`c.Writer` 必须还原**：响应加密缓冲响应体，`c.Next()` 后还原 `c.Writer`，否则 `Recover`
  在本函数返回后渲染错误会落进已用完的缓冲区。
- **响应加密失败绝不退回写明文**：丢弃已缓冲的明文，撤掉密钥头，回 500 错误体。
- **`!Enabled` 直通**：零值 `Crypto` 不做任何加解密，注解所在路由照常处理明文。
