// transport复用
// 重试
// 设置代理
// 请求可添加删除cookie
// 可设置单个请求的超时时间
// 参数按添加顺序发送
// head不自动规范化
// 支持debug模式https://github.com/kirinlabs/HttpRequest
// request重复使用
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

var (
	defaultDialTimeout     time.Duration = 30 * time.Second
	defaultResponseTimeout time.Duration
	disableCookie          bool
)

// set default timeout
func SetTimeout(dialTimeout, responseTimeout time.Duration) {
	defaultDialTimeout = dialTimeout
	defaultResponseTimeout = responseTimeout
}

func DisableCookie() {
	disableCookie = true
}

type httpProxy struct {
	isAuthProxy bool
	// isAuthProxy=false
	proxyURL string

	// isAuthProxy=true
	username string
	password string
	ip       string
	port     string
}

func (p *httpProxy) IsZero() bool {
	return p.isAuthProxy && p.ip == "" || !p.isAuthProxy && p.proxyURL == ""
}

var defaultProxy httpProxy

func SetProxy(proxyURL string) {
	defaultProxy.isAuthProxy = false
	defaultProxy.proxyURL = proxyURL
}

// AuthProxy
func SetAuthProxy(username, password, ip, port string) {
	defaultProxy.isAuthProxy = true
	defaultProxy.username = username
	defaultProxy.password = password
	defaultProxy.ip = ip
	defaultProxy.port = port
}

var defaultTransport = http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var defaultCookieJar = func() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	return jar
}()

var DefaultClient = &http.Client{
	Transport:     &defaultTransport,
	Jar:           defaultCookieJar,
	CheckRedirect: nil,
	Timeout:       defaultResponseTimeout,
}

type param struct {
	key   string
	value string
}

type Request struct {
	url    string
	req    *http.Request
	params []param

	dialTimeout     time.Duration
	responseTimeout time.Duration

	checkRedirect func(req *http.Request, via []*http.Request) error

	files  map[string]string
	resp   *http.Response
	body   []byte
	dump   []byte
	client *http.Client
	proxy  httpProxy
}

type Response struct {
	resp *http.Response
	err  error
}

func NewRequest(method, url string) *Request {
	var req Request

	var err error
	req.req, err = http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}

	return &Request{}
}

// key is canonical form of MIME-style
func (r *Request) Head(key, value string) {
	r.req.Header.Add(key, value)
}

// key is noncanonical form
func (r *Request) RawHead(key, value string) {
	r.req.Header[key] = append(r.req.Header[key], value)
}

// 可重复
func (r *Request) Param(key, value string) {
	r.params = append(r.params, param{key, value})
}

// proxyURL:http://127.0.0.1:8888
func (r *Request) SetProxy(proxyURL string) {
	if r.proxy != nil {
		panic("proxy is already set")
	}

	r.proxy = func(req *http.Request) (*url.URL, error) {
		u, _ := url.ParseRequestURI(proxyURL)
		return u, nil
	}
}

// AuthProxy
func (r *Request) SetAuthProxy(username, password, ip, port string) {
	if r.proxy != nil {
		panic("proxy is already set")
	}

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

func (r *Request) SetCheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) {
	r.checkRedirect = checkRedirect
}

func (r *Request) Do() *Response {

	client := &http.Client{
		Transport: &defaultTransport,
	}

	dialTimeout := defaultDialTimeout
	if r.dialTimeout > 0 {
		dialTimeout = r.dialTimeout
	}

	defaultTransport.DialContext = (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext

	client.Timeout = defaultResponseTimeout
	if r.responseTimeout > 0 {
		client.Timeout = r.responseTimeout
	}

	if !r.proxy.IsZero() {
		if r.proxy.isAuthProxy {
			auth := r.proxy.username + ":" + r.proxy.password
			basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			r.Head("Proxy-Authorization", basic)

			proxyURL := "http://" + r.proxy.ip + ":" + r.proxy.port
			defaultTransport.Proxy = func(req *http.Request) (*url.URL, error) {
				u, _ := url.ParseRequestURI(proxyURL)
				u.User = url.UserPassword(r.proxy.username, r.proxy.password)
				return u, nil
			}
		} else {
			http.ProxyURL()
		}
		defaultTransport.Proxy = r.proxy
	} else {

	}

	if !disableCookie {
		client.Jar = defaultCookieJar
	}

	if r.checkRedirect != nil {
		client.CheckRedirect = r.checkRedirect
	}

	var resp Response
	resp.resp, resp.err = client.Do(r.req)

	return nil
}

func Get(url string) (statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodGet, url)

	var response *http.Response
	response, err = DefaultClient.Do(req.req)
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
	case io.Reader:
		body = data.(io.Reader)
	case nil:
		body = nil
	default:
		panic("post data must be string or []byte")
	}

	var req *http.Request
	req, err = http.NewRequest(http.MethodPost, url, body)
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
