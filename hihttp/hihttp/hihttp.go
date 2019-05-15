// 重试
// 支持debug模式https://github.com/kirinlabs/HttpRequest 打印请求和请求的ID
// 文件上传
// requestwithcontext

// 参数按添加顺序发送
// 连接复用
// head不自动规范化
// 设置代理
// 设置单个请求的超时时间
// 设置重定向检查
// request重复使用
// post多种数据类型
// body json解析 存入文件
// 添加cookie
package hihttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	defaultDialTimeout       time.Duration = 30 * time.Second
	defaultResponseTimeout   time.Duration
	defaultDisableCookie     bool
	defaultKeepParamAddOrder bool
	defaultDisableKeepAlives bool
)

// set default timeout
func SetTimeout(dialTimeout, responseTimeout time.Duration) {
	defaultDialTimeout = dialTimeout
	defaultResponseTimeout = responseTimeout
}

func DisableCookie() {
	defaultDisableCookie = true
}

func KeepParamAddOrder() {
	defaultKeepParamAddOrder = true
}

func DisableKeepAlives() {
	defaultDisableKeepAlives = true
}

var httpProxys = make(map[string]httpProxy)
var defaultProxyKey = "defaultProxyKey"

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

// Proxy：http://127.0.0.1:8888
func SetProxy(proxyURL string, urls ...string) {
	hp := httpProxy{isAuthProxy: false, proxyURL: proxyURL}

	n := len(urls)
	if n == 0 {
		httpProxys[defaultProxyKey] = hp
	} else {
		for _, rawURL := range urls {
			URL, err := url.Parse(rawURL)
			if err == nil {
				httpProxys[URL.Hostname()] = hp
			}
		}
	}
}

// AuthProxy
func SetAuthProxy(username, password, ip, port string, urls ...string) {
	var hp httpProxy
	hp.isAuthProxy = true
	hp.username = username
	hp.password = password
	hp.ip = ip
	hp.port = port

	n := len(urls)
	if n == 0 {
		httpProxys[defaultProxyKey] = hp
	} else {
		for _, rawURL := range urls {
			URL, err := url.Parse(rawURL)
			if err == nil {
				httpProxys[URL.Hostname()] = hp
			}
		}
	}
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
	DisableKeepAlives:     defaultDisableKeepAlives,
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

type Request struct {
	url         string
	method      string
	heads       http.Header
	params      url.Values
	paramsOrder []string
	body        io.Reader
	cookies     []*http.Cookie

	contentType       string
	dialTimeout       time.Duration
	responseTimeout   time.Duration
	keepParamAddOrder bool
	disableCookie     bool

	checkRedirect func(req *http.Request, via []*http.Request) error
	ctx           context.Context

	files map[string]string
	resp  *http.Response
	dump  []byte
}

func NewRequest(method, url string, body io.Reader) *Request {
	var req Request
	req.method = method
	req.url = url
	req.body = body

	// var err error
	// req.req, err = http.NewRequest(method, url, body)
	// if err != nil {
	// 	panic(err)
	// }

	return &req
}

// key is canonical form of MIME-style
func (r *Request) Head(key, value string) {
	r.heads.Add(key, value)
}

// key is noncanonical form
func (r *Request) RawHead(key, value string) {
	r.heads[key] = append(r.heads[key], value)
}

func (r *Request) Param(key, value string) {
	r.params.Add(key, value)
	r.paramsOrder = append(r.paramsOrder, key)
}

func (r *Request) SetCheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) {
	r.checkRedirect = checkRedirect
}

func (r *Request) WithContext(ctx context.Context) {
	r.ctx = ctx
}

func (r *Request) AddCookie(c *http.Cookie) {
	r.cookies = append(r.cookies, c)
}

func (r *Request) KeepParamAddOrder() {
	r.keepParamAddOrder = true
}

func (r *Request) DisableCookie() {
	r.disableCookie = true
}

func (r *Request) proxyFunc(req *http.Request) (*url.URL, error) {
	if req == nil || req.URL == nil || len(httpProxys) == 0 {
		return nil, nil
	}

	hp, ok := httpProxys[req.URL.Hostname()]
	if ok {
		if hp.IsZero() {
			return nil, nil
		}
	} else {
		hp, ok = httpProxys[defaultProxyKey]
		if !ok || hp.IsZero() {
			return nil, nil
		}
	}

	if hp.isAuthProxy {
		proxyURL := "http://" + hp.ip + ":" + hp.port
		u, _ := url.ParseRequestURI(proxyURL)
		u.User = url.UserPassword(hp.username, hp.password)
		return u, nil
	}

	u, _ := url.ParseRequestURI(hp.proxyURL)
	return u, nil
}

func (r *Request) Do() (*Response, error) {

	client := &http.Client{
		Transport: &defaultTransport,
	}

	client.Timeout = defaultResponseTimeout
	if r.responseTimeout > 0 {
		client.Timeout = r.responseTimeout
	}

	defaultTransport.Proxy = r.proxyFunc

	if r.checkRedirect != nil {
		client.CheckRedirect = r.checkRedirect
	}

	req, err := http.NewRequest(r.method, r.url, r.body)
	if err != nil {
		return nil, err
	}

	if r.ctx != nil {
		req = req.WithContext(r.ctx)
	}

	if r.heads != nil {
		for key, value := range r.heads {
			req.Header[key] = value
		}
	}

	keepParamAddOrder := defaultKeepParamAddOrder || r.keepParamAddOrder
	var queryParam string
	if keepParamAddOrder {
		if r.params != nil {
			len := len(r.paramsOrder)
			var buf strings.Builder
			for i := 0; i < len; i++ {
				vs := r.params[r.paramsOrder[i]]
				keyEscaped := url.QueryEscape(r.paramsOrder[i])
				for _, v := range vs {
					if buf.Len() > 0 {
						buf.WriteByte('&')
					}
					buf.WriteString(keyEscaped)
					buf.WriteByte('=')
					buf.WriteString(url.QueryEscape(v))
				}
			}
			queryParam = buf.String()
		}
	} else {
		queryParam = r.params.Encode()
	}

	if strings.Index(r.url, "?") == -1 {
		r.url = r.url + "?" + queryParam
	} else {
		if strings.HasSuffix(r.url, "&") {
			r.url += queryParam
		} else {
			r.url += "&" + queryParam
		}
	}

	if req.Method == http.MethodPost && r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}

	disableCookie := defaultDisableCookie || r.disableCookie
	if !disableCookie {
		defaultCookieJar.SetCookies(req.URL, r.cookies)
		client.Jar = defaultCookieJar
	}

	var resp Response
	resp.resp, err = client.Do(req)

	return &resp, err
}

type Response struct {
	resp *http.Response
	err  error
}

// r 判空
func (r *Response) StatusCode() int {
	if r == nil || r.resp == nil {
		return 0
	}

	return r.resp.StatusCode
}

func (r *Response) Headers() http.Header {
	if r == nil || r.resp == nil {
		return nil
	}

	return r.resp.Header
}

func (r *Response) Cookie() []*http.Cookie {
	if r == nil || r.resp == nil {
		return nil
	}

	return r.resp.Cookies()
}

func (r *Response) Location() (string, error) {
	if r == nil || r.resp == nil {
		return "", errors.New("hihttp:http response is nil pointer")
	}

	location, err := r.resp.Location()
	if err != nil {
		return "", err
	}

	return location.String(), nil
}

// 超时时间包括body的读取 请求结束后要尽快读取
func (r *Response) Body() (body []byte, err error) {
	if r == nil || r.resp == nil {
		return nil, errors.New("hihttp:http response is nil pointer")
	}

	if r.resp.Body == nil {
		return nil, nil
	}

	defer r.resp.Body.Close()
	if r.resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(r.resp.Body)
		if err != nil {
			return nil, err
		}
		body, err = ioutil.ReadAll(reader)
	} else {
		body, err = ioutil.ReadAll(r.resp.Body)
	}

	return
}

func (r *Response) FromJson(v interface{}) error {
	resp, err := r.Body()
	if err != nil {
		return err
	}

	return json.Unmarshal(resp, v)
}

func (r *Response) ToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := r.Body()
	if err != nil {
		return err
	}

	_, err = io.Copy(f, bytes.NewReader(resp))
	return err
}

func Get(url string) (statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodGet, url, nil)

	var response *Response
	response, err = req.Do()
	if err != nil {
		return
	}

	statusCode = response.StatusCode()
	resp, err = response.Body()

	return
}

type PostOption struct {
	ContentType    string
	JsonEscapeHTML bool
}

func Post(url string, data interface{}, opt ...PostOption) (statusCode int, resp []byte, err error) {

	var body io.Reader
	switch t := data.(type) {
	case string:
		bf := bytes.NewBufferString(t)
		body = ioutil.NopCloser(bf)
	case fmt.Stringer:
		bf := bytes.NewBufferString(t.String())
		body = ioutil.NopCloser(bf)
	case []byte:
		bf := bytes.NewBuffer(t)
		body = ioutil.NopCloser(bf)
	case io.Reader:
		body = data.(io.Reader)
	case nil:
		body = nil
	default:
		buf := bytes.NewBuffer(nil)
		enc := json.NewEncoder(buf)
		if len(opt) > 0 {
			enc.SetEscapeHTML(opt[0].JsonEscapeHTML)
		}
		if err = enc.Encode(data); err != nil {
			return
		}
		body = ioutil.NopCloser(buf)
	}

	req := NewRequest(http.MethodPost, url, body)
	if err != nil {
		return
	}

	if len(opt) < 0 {
		req.contentType = defaultContentType
	} else {
		req.contentType = opt[0].ContentType
	}

	var response *Response
	response, err = req.Do()
	if err != nil {
		return
	}

	statusCode = response.resp.StatusCode
	resp, err = response.Body()

	return
}
