// transport复用
// 重试
// 请求可添加删除cookie
// 参数按添加顺序发送
// 支持debug模式https://github.com/kirinlabs/HttpRequest
// request重复使用
// 文件上传

// head不自动规范化
// 设置代理
// 可设置单个请求的超时时间
// 设置重定向检查
package hihttp

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

var (
	defaultDialTimeout       time.Duration = 30 * time.Second
	defaultResponseTimeout   time.Duration
	defaultProxy             httpProxy
	disableCookie            bool
	defaultKeepParamAddOrder bool
	defaultDisableKeepAlives bool
)

// set default timeout
func SetTimeout(dialTimeout, responseTimeout time.Duration) {
	defaultDialTimeout = dialTimeout
	defaultResponseTimeout = responseTimeout
}

func DisableCookie() {
	disableCookie = true
}

func KeepParamAddOrder() {
	defaultKeepParamAddOrder = true
}

func DisableKeepAlives() {
	defaultDisableKeepAlives = true
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

// http://127.0.0.1:8888
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

	contentType       string
	dialTimeout       time.Duration
	responseTimeout   time.Duration
	keepParamAddOrder bool

	checkRedirect func(req *http.Request, via []*http.Request) error

	files  map[string]string
	resp   *http.Response
	dump   []byte
	client *http.Client
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

func (r *Request) KeepParamAddOrder() {
	r.keepParamAddOrder = true
}

func (r *Request) Do() (*Response, error) {

	client := &http.Client{
		Transport: &defaultTransport,
	}

	client.Timeout = defaultResponseTimeout
	if r.responseTimeout > 0 {
		client.Timeout = r.responseTimeout
	}

	if !defaultProxy.IsZero() {
		if defaultProxy.isAuthProxy {
			proxyURL := "http://" + defaultProxy.ip + ":" + defaultProxy.port
			defaultTransport.Proxy = func(req *http.Request) (*url.URL, error) {
				u, _ := url.ParseRequestURI(proxyURL)
				u.User = url.UserPassword(defaultProxy.username, defaultProxy.password)
				return u, nil
			}
		} else {
			defaultTransport.Proxy = func(req *http.Request) (*url.URL, error) {
				u, _ := url.ParseRequestURI(defaultProxy.proxyURL)
				return u, nil
			}
		}
	}

	if !disableCookie {
		client.Jar = defaultCookieJar
	}

	if r.checkRedirect != nil {
		client.CheckRedirect = r.checkRedirect
	}

	req, err := http.NewRequest(r.method, r.url, r.body)
	if err != nil {
		return nil, err
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

	req := NewRequest(http.MethodPost, url, body)
	if err != nil {
		return
	}

	if len(contentType) < 0 {
		req.contentType = defaultContentType
	} else {
		req.contentType = contentType[0]
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
