// transport复用
// 重试
// 设置代理
// 请求可添加删除cookie
// 可设置单个请求的超时时间
// 参数按添加顺序发送
// head不自动规范化
package hihttp

import (
	"compress/gzip"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const (
	dialTimeout = 30 * time.Second
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
	//Timeout:       0,
}

type request struct {
	url     string
	req     *http.Request
	params  map[string]string
	mparams [][2]string
	files   map[string]string
	resp    *http.Response
	body    []byte
	dump    []byte
	client  *http.Client
}

func NewRequest(method, url string) *request {
	return &request{}
}

func Get(url string) (statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodGet, url)
	var response *http.Response
	response, err = defaultClient.Do(req.req)
	if err != nil {
		return
	}

	defer response.Body.Close()

	statusCode = response.StatusCode

	if response.Header.Get("Content-Encoding") == "gzip" {
		var reader *gzip.Reader
		reader, err = gzip.NewReader(response.Body)
		if err != nil {
			return
		}
		resp, err = ioutil.ReadAll(reader)
	} else {
		resp, err = ioutil.ReadAll(response.Body)
	}

	return
}

type ContentTypeType string

const (
	FormURLEncoded = ContentTypeType("")
)

func DefaultContentType(contentType ContentTypeType) {

}

func Post(url string, data interface{}, contentType ...string) (statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodPost, url)
	var response *http.Response
	response, err = defaultClient.Do(req.req)
	if err != nil {
		return
	}

	defer response.Body.Close()

	statusCode = response.StatusCode

	if response.Header.Get("Content-Encoding") == "gzip" {
		var reader *gzip.Reader
		reader, err = gzip.NewReader(response.Body)
		if err != nil {
			return
		}
		data, err = ioutil.ReadAll(reader)
	} else {
		data, err = ioutil.ReadAll(response.Body)
	}

	return
}
