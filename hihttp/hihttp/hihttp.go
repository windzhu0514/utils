// transport复用
// 重试
// 设置代理
// 请求可添加删除cookie
// 可设置单个请求的超时时间
// 参数按添加顺序发送
// head不自动规范化
// 支持debug模式https://github.com/kirinlabs/HttpRequest
package hihttp

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

var DefaultClient = &http.Client{
	Transport: &http.Transport{
		//Proxy: http.ProxyFromEnvironment,
		Proxy: func(req *http.Request) (*url.URL, error) {
			u, _ := url.ParseRequestURI("http://127.0.0.1:8888")
			return u, nil
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
	Jar: func() http.CookieJar {
		jar, _ := cookiejar.New(nil)
		return jar
	}(),
	CheckRedirect: nil,
	//Timeout:       0,
}

type param struct {
	key   string
	value string
}

type request struct {
	url     string
	req     *http.Request
	params  []param
	mparams [][2]string
	files   map[string]string
	resp    *http.Response
	body    []byte
	dump    []byte
	client  *http.Client
	proxy   func(*http.Request) (*url.URL, error)
}

func NewRequest(method, url string) *request {
	return &request{}
}

func (r *request) Head(key, value string) {
	r.req.Header.Add(key, value)
}

func (r *request) RawHead(key, value string) {
	r.req.Header[key] = append(r.req.Header[key], value)
}

// 可重复 可排序
func (r *request) Param(key, value string) {
	r.params = append(r.params, param{key, value})
}

// proxyURL:http://127.0.0.1:8888
func (r *request) SetProxy(proxyURL string) {
	r.proxy = func(req *http.Request) (*url.URL, error) {
		u, _ := url.ParseRequestURI(proxyURL)
		return u, nil
	}
}

// AuthProxy
func (r *request) SetAuthProxy(username, password, ip, port string) {
	auth := username + ":" + password
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	r.Head("Proxy-Authorization", basic)

	proxyURL := "http://" + ip + ":" + port
	r.proxy = func(req *http.Request) (*url.URL, error) {
		u, _ := url.ParseRequestURI(proxyURL)
		u.User = url.UserPassword(username, password)
		return u, nil
	}
}

func DisableCookie() {
	DefaultClient.Jar = nil
}

func Get(url string) (statusCode int, resp []byte, err error) {
	var req *http.Request
	req, err = http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}

	var response *http.Response
	response, err = DefaultClient.Do(req)
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

// Content-Type
const (
	CTTextHtml          = "text/html"
	CTTextPlain         = "text/plain"
	CTApplicationJson   = "application/json"
	CTApplicationXml    = "application/xml"
	CTApplicationForm   = "application/x-www-form-urlencoded"
	CTApplicationStream = "application/octet-stream"
	CTMultipartFormData = "multipart/form-data"
)

var defaultContentType = CTTextPlain

func SetContentType(contentType string) {
	defaultContentType = contentType
}

func Post(url string, data interface{}, contentType ...string) (statusCode int, resp []byte, err error) {

	var body io.Reader
	switch t := data.(type) {
	case string:
		bf := bytes.NewBufferString(t)
		body = ioutil.NopCloser(bf)
	case []byte:
		bf := bytes.NewBuffer(t)
		body = ioutil.NopCloser(bf)
	default:
		panic("post data must be string or []byte")
	}

	var req *http.Request
	req, err = http.NewRequest(http.MethodGet, url, body)
	if err != nil {
		return
	}

	if len(contentType) < 0 {
		req.Header.Set("Content-Type", defaultContentType)
	} else {
		req.Header.Set("Content-Type", contentType[0])
	}

	var response *http.Response
	response, err = DefaultClient.Do(req)
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
