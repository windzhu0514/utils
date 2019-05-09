package httpclient

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	maxIdleConns        = 100
	maxIdleConnsPerHost = 10
	idleConnTimeout     = 90 * time.Second
)

var defaultSetting = HttpSettings{
	UserAgent:        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.89 Safari/537.36",
	ConnectTimeout:   30 * time.Second, // 拨号超时时间
	ReadWriteTimeout: 30 * time.Second, // 限制一次请求的时间
	Gzip:             true,
	DumpBody:         true,
	TlsClientConfig:  &tls.Config{InsecureSkipVerify: true}, //default ignore cer check
	EnableCookie:     true,
	ManualSetCookie:  false,
	Transport: &http.Transport{
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		IdleConnTimeout:     idleConnTimeout,
	},
	Proxy: func(req *http.Request) (*url.URL, error) {
		u, _ := url.ParseRequestURI("http://127.0.0.1:8888")
		return u, nil
	},
}

var defaultCookieJar http.CookieJar
var settingMutex sync.Mutex

// createDefaultCookie creates a global cookiejar to store cookies.
func createDefaultCookie() {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultCookieJar, _ = cookiejar.New(nil)
}

// Overwrite default settings
func SetDefaultSetting(setting HttpSettings) {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultSetting = setting
	if defaultSetting.ConnectTimeout == 0 {
		defaultSetting.ConnectTimeout = 60 * time.Second
	}
	if defaultSetting.ReadWriteTimeout == 0 {
		defaultSetting.ReadWriteTimeout = 60 * time.Second
	}
	if defaultSetting.EnableCookie {
		defaultSetting.Cookies, _ = cookiejar.New(nil)
	}
}

// return *HttpRequest with specific method
func NewRequest(rawurl, method string) *HttpRequest {
	var resp http.Response
	u, err := url.Parse(rawurl)
	if err != nil {
		log.Fatal(err)
	}
	req := &http.Request{
		URL:        u,
		Method:     method,
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}

	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			log.Printf("GetConn 需要一个连接: %+v\n", hostPort)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			log.Printf("GotConn 获取到连接: %+v\n", connInfo)
		},
		ConnectStart: func(network, addr string) {
			log.Printf("ConnectStart 开始创建新连接: %s %s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			log.Printf("ConnectDone 创建新连接结束: %s %s %v\n", network, addr, err)
		},
		PutIdleConn: func(err error) {
			log.Printf("PutIdleConn 连接放入空闲队列:%v\n", err)
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	return &HttpRequest{
		url:     rawurl,
		req:     req,
		params:  map[string]string{},
		files:   map[string]string{},
		setting: defaultSetting,
		resp:    &resp,
	}
}

// Get returns *HttpRequest with GET method.
func Get(url string) *HttpRequest {
	return NewRequest(url, "GET")
}

// Post returns *HttpRequest with POST method.
func Post(url string) *HttpRequest {
	return NewRequest(url, "POST")
}

// Put returns *HttpRequest with PUT method.
func Put(url string) *HttpRequest {
	return NewRequest(url, "PUT")
}

// Delete returns *HttpRequest DELETE method.
func Delete(url string) *HttpRequest {
	return NewRequest(url, "DELETE")
}

// Head returns *HttpRequest with HEAD method.
func Head(url string) *HttpRequest {
	return NewRequest(url, "HEAD")
}

// HttpSettings
type HttpSettings struct {
	ShowDebug        bool
	UserAgent        string
	ConnectTimeout   time.Duration
	ReadWriteTimeout time.Duration
	TlsClientConfig  *tls.Config
	Proxy            func(*http.Request) (*url.URL, error)
	CheckRedirect    func(req *http.Request, via []*http.Request) error
	Transport        http.RoundTripper
	Cookies          http.CookieJar
	EnableCookie     bool
	Gzip             bool
	DumpBody         bool
	ManualSetCookie  bool
}

// HttpRequest provides more useful methods for requesting one url than http.Request.
type HttpRequest struct {
	url     string
	req     *http.Request
	params  map[string]string
	mparams [][2]string
	files   map[string]string
	setting HttpSettings
	resp    *http.Response
	body    []byte
	dump    []byte
	client  *http.Client
}

// get request
func (b *HttpRequest) GetRequest() *http.Request {
	return b.req
}

// get request params
func (b *HttpRequest) GetRequestParams() *map[string]string {
	return &b.params
}

// Change request settings
func (b *HttpRequest) Setting(setting HttpSettings) *HttpRequest {
	b.setting = setting
	return b
}

// func(*http.Request) (*url.URL, error)
func (b *HttpRequest) SetCheckRedirect(selfRedirect func(req *http.Request, via []*http.Request) error) *HttpRequest {
	b.setting.CheckRedirect = selfRedirect
	return b
}

// SetBasicAuth sets the request's Authorization header to use HTTP Basic Authentication with the provided username and password.
func (b *HttpRequest) SetBasicAuth(username, password string) *HttpRequest {
	b.req.SetBasicAuth(username, password)
	return b
}

// SetEnableCookie sets enable/disable cookiejar
func (b *HttpRequest) SetEnableCookie(enable bool) *HttpRequest {
	b.setting.EnableCookie = enable
	return b
}

// SetEnableCookie sets enable/disable cookiejar
func (b *HttpRequest) SetManualSetCookie(enable bool) *HttpRequest {
	b.setting.ManualSetCookie = enable
	return b
}

//Set cookie
func (b *HttpRequest) SetCookieJar(cookiejar http.CookieJar) *HttpRequest {
	b.setting.Cookies = cookiejar
	return b
}

// SetUserAgent sets User-Agent header field
func (b *HttpRequest) SetUserAgent(useragent string) *HttpRequest {
	b.setting.UserAgent = useragent
	return b
}

//Reset request URL, 重置请求的URL
func (b *HttpRequest) ResetRequestURL(rawurl string) *HttpRequest {
	u, err := url.Parse(rawurl)
	if err != nil {
		log.Fatal(err)
	}
	b.req.URL = u
	b.url = rawurl
	return b
}

// Reset request Method
func (b *HttpRequest) ResetRequestMethod(method string) *HttpRequest {
	b.req.Method = method
	return b
}

// Debug sets show debug or not when executing request.
func (b *HttpRequest) Debug(isdebug bool) *HttpRequest {
	b.setting.ShowDebug = isdebug
	return b
}

// Dump Body.
func (b *HttpRequest) DumpBody(isdump bool) *HttpRequest {
	b.setting.DumpBody = isdump
	return b
}

// return the DumpRequest
func (b *HttpRequest) DumpRequest() []byte {
	return b.dump
}

// SetTimeout sets connect time out and read-write time out for Request.
func (b *HttpRequest) SetTimeout(connectTimeout, readWriteTimeout time.Duration) *HttpRequest {
	b.setting.ConnectTimeout = connectTimeout
	b.setting.ReadWriteTimeout = readWriteTimeout
	return b
}

// SetTLSClientConfig sets tls connection configurations if visiting https url.
func (b *HttpRequest) SetTLSClientConfig(config *tls.Config) *HttpRequest {
	b.setting.TlsClientConfig = config
	return b
}

//设置自定义的header
func (b *HttpRequest) SetDefaultHeader(defaultHeader http.Header) *HttpRequest {
	b.GetRequest().Header = defaultHeader
	return b
}

// Header add header item string in request.
func (b *HttpRequest) Header(key, value string) *HttpRequest {
	b.req.Header.Set(key, value)
	return b
}

// delete header
func (b *HttpRequest) DelHeader(key string) *HttpRequest {
	b.req.Header.Del(key)
	return b
}

// Headers in request.
func (b *HttpRequest) Headers(headers map[string]string) *HttpRequest {
	for k, v := range headers {
		b.req.Header.Set(k, v)
	}
	return b
}

// Set HOST
func (b *HttpRequest) SetHost(host string) *HttpRequest {
	b.req.Host = host
	return b
}

// Set the protocol version for incoming requests.
// Client requests always use HTTP/1.1.
func (b *HttpRequest) SetProtocolVersion(vers string) *HttpRequest {
	if len(vers) == 0 {
		vers = "HTTP/1.1"
	}

	major, minor, ok := http.ParseHTTPVersion(vers)
	if ok {
		b.req.Proto = vers
		b.req.ProtoMajor = major
		b.req.ProtoMinor = minor
	}

	return b
}

// SetCookie add cookie into request.
func (b *HttpRequest) SetCookie(cookie *http.Cookie) *HttpRequest {
	b.req.Header.Add("Cookie", cookie.String())
	return b
}

// Set transport to
func (b *HttpRequest) SetTransport(transport http.RoundTripper) *HttpRequest {
	b.setting.Transport = transport
	return b
}

// Set http proxy
// example:
//
//	func(req *http.Request) (*url.URL, error) {
// 		u, _ := url.ParseRequestURI("http://127.0.0.1:8118")
// 		return u, nil
// 	}
func (b *HttpRequest) SetProxy(proxy func(*http.Request) (*url.URL, error)) *HttpRequest {
	b.setting.Proxy = proxy
	return b
}

// set AuthProxy
func (b *HttpRequest) SetAuthProxy(proxyUser, proxyPass, proxyIp, ProxyPort string) {
	auth := proxyUser + ":" + proxyPass
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	b.Header("Proxy-Authorization", basic)

	proxyUrl := "http://" + proxyIp + ":" + ProxyPort
	b.SetProxy(func(req *http.Request) (*url.URL, error) {
		u, _ := url.ParseRequestURI(proxyUrl)
		u.User = url.UserPassword(proxyUser, proxyPass)
		return u, nil
	})
}

// get http StatusCode
func (b *HttpRequest) GetSatusCode() (int, error) {
	resp, err := b.getResponse()
	if err != nil {
		return 0, err
	}

	return resp.StatusCode, nil
}

// get http location
func (b *HttpRequest) GetLocation() (string, error) {
	resp, err := b.getResponse()
	if err != nil {
		return "", err
	}

	location, err := resp.Location()
	if err != nil {
		return "", err
	}

	return location.String(), nil
}

// Is Forbidden
func (b *HttpRequest) IsForbidden() bool {
	code, err := b.GetSatusCode()
	if err == nil {
		return code == http.StatusForbidden ||
			code == http.StatusRequestTimeout
	} else {
		err_msg := err.Error()
		if strings.Contains(err_msg, "i/o timeout") ||
			strings.Contains(err_msg, "connection refused") {
			return true
		}
	}

	return false
}

// Param adds query param in to request.
// params build query string as ?key1=value1&key2=value2...
func (b *HttpRequest) Param(key, value string) *HttpRequest {
	b.params[key] = value
	return b
}

func (b *HttpRequest) MultiParam(key, value string) *HttpRequest {
	var arg = [2]string{key, value}
	b.mparams = append(b.mparams, arg)
	return b
}

func (b *HttpRequest) PostFile(formname, filename string) *HttpRequest {
	b.files[formname] = filename
	return b
}

// Body adds request raw body.
// it supports string and []byte.
func (b *HttpRequest) Body(data interface{}) *HttpRequest {
	switch t := data.(type) {
	case string:
		bf := bytes.NewBufferString(t)
		b.req.Body = ioutil.NopCloser(bf)
		b.req.ContentLength = int64(len(t))
	case []byte:
		bf := bytes.NewBuffer(t)
		b.req.Body = ioutil.NopCloser(bf)
		b.req.ContentLength = int64(len(t))
	}
	return b
}

// JsonBody adds request raw body encoding by JSON.
func (b *HttpRequest) JsonBody(obj interface{}) (*HttpRequest, error) {
	if b.req.Body == nil && obj != nil {
		buf := bytes.NewBuffer(nil)
		enc := json.NewEncoder(buf)
		if err := enc.Encode(obj); err != nil {
			return b, err
		}
		b.req.Body = ioutil.NopCloser(buf)
		b.req.ContentLength = int64(buf.Len())
		b.req.Header.Set("Content-Type", "application/json")
	}
	return b, nil
}

func (b *HttpRequest) buildUrl(paramBody string) {
	// build GET url with query string
	if b.req.Method == "GET" && len(paramBody) > 0 {
		if strings.Index(b.url, "?") != -1 {
			b.url += "&" + paramBody
		} else {
			b.url = b.url + "?" + paramBody
		}
		return
	}

	// build POST/PUT/PATCH url and body
	if (b.req.Method == "POST" || b.req.Method == "PUT" || b.req.Method == "PATCH") && b.req.Body == nil {
		// with files
		if len(b.files) > 0 {
			pr, pw := io.Pipe()
			bodyWriter := multipart.NewWriter(pw)
			go func() {
				for formname, filename := range b.files {
					fileWriter, err := bodyWriter.CreateFormFile(formname, filename)
					if err != nil {
						log.Fatal(err)
					}
					fh, err := os.Open(filename)
					if err != nil {
						log.Fatal(err)
					}
					//iocopy
					_, err = io.Copy(fileWriter, fh)
					fh.Close()
					if err != nil {
						log.Fatal(err)
					}
				}
				for k, v := range b.params {
					bodyWriter.WriteField(k, v)
				}
				bodyWriter.Close()
				pw.Close()
			}()
			b.Header("Content-Type", bodyWriter.FormDataContentType())
			b.req.Body = ioutil.NopCloser(pr)
			return
		}

		// with params
		if len(paramBody) > 0 {
			b.Header("Content-Type", "application/x-www-form-urlencoded")
			b.Body(paramBody)
		}
	}
}

func (b *HttpRequest) getResponse() (*http.Response, error) {
	if b.resp.StatusCode != 0 {
		return b.resp, nil
	}
	resp, err := b.SendOut()
	if err != nil {
		return nil, err
	}
	b.resp = resp
	if b.setting.ManualSetCookie {
		b.readSetCookies()
	}
	return resp, nil
}

func (b *HttpRequest) SendOut() (*http.Response, error) {
	var paramBody string
	if len(b.params) > 0 {
		var buf bytes.Buffer
		for k, v := range b.params {
			if k != "" {
				buf.WriteString(url.QueryEscape(k))
				buf.WriteByte('=')
			}
			buf.WriteString(url.QueryEscape(v))
			buf.WriteByte('&')
		}
		if len(b.mparams) > 0 {
			for _, p := range b.mparams {
				if len(p) == 2 && p[0] != "" {
					buf.WriteString(url.QueryEscape(p[0]))
					buf.WriteByte('=')
				}
				buf.WriteString(url.QueryEscape(p[1]))
				buf.WriteByte('&')
			}
		}
		paramBody = buf.String()
		paramBody = paramBody[0 : len(paramBody)-1]
	}

	b.buildUrl(paramBody)
	tmpURL, err := url.Parse(b.url)
	if err != nil {
		return nil, err
	}

	b.req.URL = tmpURL

	if b.setting.ManualSetCookie {
		b.addCooike()
	}

	trans := b.setting.Transport

	if trans == nil {
		// create default transport
		trans = &http.Transport{
			TLSClientConfig: b.setting.TlsClientConfig,
			Proxy:           b.setting.Proxy,
			DialContext: (&net.Dialer{
				Timeout:   b.setting.ConnectTimeout, //  30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	} else {
		// if b.transport is *http.Transport then set the settings.
		if t, ok := trans.(*http.Transport); ok {
			if b.setting.TlsClientConfig != nil {
				t.TLSClientConfig = b.setting.TlsClientConfig
			}
			if b.setting.Proxy != nil {
				t.Proxy = b.setting.Proxy
			}

			if t.DialContext == nil {
				t.DialContext = (&net.Dialer{
					Timeout:   b.setting.ConnectTimeout, //  30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext
			}
		}
	}

	var jar http.CookieJar = nil
	if b.setting.EnableCookie && !b.setting.ManualSetCookie {
		if b.setting.Cookies == nil {
			b.setting.Cookies, _ = cookiejar.New(nil)
		}
		jar = b.setting.Cookies
	}

	client := &http.Client{
		Transport:     trans,
		Jar:           jar,
		CheckRedirect: b.setting.CheckRedirect,
		Timeout:       b.setting.ReadWriteTimeout,
	}

	b.client = client

	if b.setting.UserAgent != "" {
		if _, ok := b.req.Header["User-Agent"]; !ok {
			b.req.Header.Set("User-Agent", b.setting.UserAgent)
		}
	}

	if b.setting.ShowDebug {
		dump, err := httputil.DumpRequest(b.req, b.setting.DumpBody)
		if err != nil {
			log.Println(err.Error())
		}
		b.dump = dump
	}

	return client.Do(b.req)
}

// 获取请求body 附带检查code
func (b *HttpRequest) StringWithCheckCode() (string, error) {
	data, err := b.Bytes()
	if err != nil {
		return "", err
	}

	code, err := b.GetSatusCode()
	if err != nil {
		return string(data), err
	}

	if code >= http.StatusBadRequest {
		return string(data), fmt.Errorf("response error:%d %s", code, http.StatusText(code))
	}

	return string(data), nil
}

// String returns the body string in response.
// it calls Response inner.
func (b *HttpRequest) String() (string, error) {
	data, err := b.Bytes()
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Bytes returns the body []byte in response.
// it calls Response inner.
func (b *HttpRequest) Bytes() ([]byte, error) {
	if b.body != nil {
		return b.body, nil
	}

	// ctx, cancel := context.WithTimeout(b.req.Context(), b.setting.ReadWriteTimeout)
	// defer cancel()
	// b.req = b.req.WithContext(ctx)

	resp, err := b.getResponse()
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if b.setting.Gzip && resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		b.body, err = ioutil.ReadAll(reader)
	} else {
		b.body, err = ioutil.ReadAll(resp.Body)
	}

	// iter := reflect.ValueOf(b.client.Transport.(*http.Transport)).Elem().FieldByName("idleConn").MapRange()
	// for iter.Next() {
	// 	fmt.Print(iter.Key(), iter.Value(), "\n")
	// 	fmt.Print("conn:")
	// 	for i := 0; i < iter.Value().Len(); i++ {
	// 		fmt.Print(iter.Value().Index(i).Elem().FieldByName("conn"), " ")
	// 	}
	// 	fmt.Println()
	// }

	mapIdleConn := reflect.ValueOf(b.client.Transport.(*http.Transport)).Elem().FieldByName("idleConn")
	if mapIdleConn.IsValid() && !mapIdleConn.IsNil() {
		fmt.Print("idleConn:")
		iter := mapIdleConn.MapRange()
		for iter.Next() {
			fmt.Print(iter.Key(), iter.Value(), "\n")
			if iter.Value().IsValid() && !iter.Value().IsNil() {
				fmt.Print("Conn:")
				for i := 0; i < iter.Value().Len(); i++ {
					fmt.Print(iter.Value().Index(i).Elem().FieldByName("conn"), " ")
				}
				fmt.Println()
			}
		}
	}

	return b.body, err
}

// ToFile saves the body data in response to one file.
// it calls Response inner.
func (b *HttpRequest) ToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := b.getResponse()
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return nil
	}
	defer resp.Body.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// ToJson returns the map that marshals from the body bytes as json in response .
// it calls Response inner.
func (b *HttpRequest) ToJson(v interface{}) error {
	data, err := b.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ToXml returns the map that marshals from the body bytes as xml in response .
// it calls Response inner.
func (b *HttpRequest) ToXml(v interface{}) error {
	data, err := b.Bytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, v)
}

// Response executes request client gets response mannually.
func (b *HttpRequest) Response() (*http.Response, error) {
	return b.getResponse()
}

// Reset reset HttpRequest to its initial state
func (b *HttpRequest) Reset() {
	var resp http.Response
	b.resp = &resp
	b.body = nil
	b.dump = nil
}
