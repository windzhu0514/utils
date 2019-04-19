package httpclient

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"testing"
	"time"
)

func TestDialer(t *testing.T) {
	var client = http.Client{
		//Transport: defaultTransport,
		Jar: func() http.CookieJar {
			jar, _ := cookiejar.New(nil)
			return jar
		}(),
	}

	req, _ := http.NewRequest("GET", "http://www.baidu.com", nil)

	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			fmt.Printf("GetConn 需要一个连接: %+v\n", hostPort)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Printf("GotConn 获取到连接: %+v\n", connInfo)
		},
		ConnectStart: func(network, addr string) {
			fmt.Printf("ConnectStart 开始创建新连接: %s %s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Printf("ConnectDone 新连接创建成功: %s %s %v\n", network, addr, err)
		},
		PutIdleConn: func(err error) {
			fmt.Println("PutIdleConn 连接放入空闲队列")
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	for i := 0; i < 100; i++ {
		fmt.Println(time.Now().String())
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return
		}
		// _, err := http.DefaultTransport.RoundTrip(req)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		//fmt.Println(string(data))
		fmt.Println("请求成功")
		time.Sleep(time.Second * 3)
	}
}

func TestGet(t *testing.T) {
	code, data, err := go_exercise.Get("http://www.baidu.com")
	fmt.Println(code, string(data), err)
}
