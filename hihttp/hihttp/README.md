# hihttp

hihttp 是 golang http 库客户端的简单封装，实现了一些方便开发的常用功能。

## 功能：

- **参数按添加顺序发送**
- **transport 连接复用**
- **head 不自动规范化**
- **代理**
  1. 设置默认代理
  2. 设置不同 url 对应的代理
- **单个请求的超时时间**
- **重定向检查**
- **添加 cookie**
- **支持 context 传入**
- **post 多种数据类型**
- **json 结果解析为结构体**
- **结果存入文件**

## TODO:

- 重试
- 支持 debug 模式https://github.com/kirinlabs/HttpRequest 打印请求和请求的 ID
- 文件上传
- 代理选择器 每个请求轮换/每多少次轮换
