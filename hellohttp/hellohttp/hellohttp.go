// transport复用
// conn.SetDeadline（ReadWriteTimeout）调整为一个小时
// 重试
// 设置代理
// 请求可添加删除cookie
// 可设置单个请求的超时时间
// 参数按添加顺序发送
// head不自动规范化
package httpclient

import (
	"net"
	"net/http"
	"time"
)

var defaultClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
	Jar:           nil,
	CheckRedirect: nil,
	Timeout:       nil,
}
