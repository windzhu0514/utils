package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

import "github.com/windzhu0514/utils/httpclient/httpclient"

func main() {

	// go func() {
	// 	fmt.Println(http.ListenAndServe(":9290", nil))
	// }()

	// ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	time.Sleep(5 * time.Minute)
	// 	fmt.Fprintln(w, "Hello, client")
	// }))
	// defer ts.Close()

	//Test("")
	bje2goQueryCoach()
	fmt.Println("发送结束")

	chExit := make(chan os.Signal, 1)
	signal.Notify(chExit, syscall.SIGINT)
	<-chExit
}

func Test(URLTest string) {
	URLs := []string{
		"https://github.com/",
		"https://www.google.com/",
		"http://kysp.ycjyjt.com/",               // 宜昌
		"http://www.hn96520.com/",               // 河南
		"https://www.changtu.com/",              // 畅途
		"https://www.baidu.com/",                // 百度
		"http://www.4006510871.cn/ticket/home/", // 云南
		"http://www.e2go.com.cn/",               // 北京
	}

	for i := 0; i < 5; i++ {
		go func() {
			fmt.Println(time.Now().String())
			req := httpclient.Get(URLs[i])
			//req := httpclient.Get(URLTest)
			req.SetTimeout(30*time.Second, 30*time.Second)
			_, err := req.String()
			if err != nil {
				fmt.Println(time.Now().String())
				fmt.Printf("请求失败:%s\n", err.Error())
			} else {
				fmt.Println("请求成功")
			}

			time.Sleep(time.Second * 10)
		}()
	}
}

func bje2goQueryCoach() {
	url := "http://118.24.183.172:6001/InnerQueryCoaches"

	for i := 0; i < 10; i++ {
		go func() {
			payload := strings.NewReader("jsonStr=%7B%22siteId%22%3A35%2C%22method%22%3A%22InnerQueryCoaches%22%2C%22data%22%3A%7B%22departure%22%3A%22%E6%A8%AA%E5%8E%BF%22%2C%22departureCode%22%3A%22450127%22%2C%22dptEnNname%22%3A%22%22%2C%22dptStation%22%3A%22%22%2C%22dptStationCode%22%3A%22%22%2C%22destination%22%3A%22%E8%B4%B5%E6%B8%AF%E5%B8%82%22%2C%22destinationCode%22%3A%22450800%22%2C%22destinationEnName%22%3A%22%22%2C%22dptDate%22%3A%222019-04-10%22%7D%7D")

			req, err := http.NewRequest("POST", url, payload)
			if err != nil {
				fmt.Println(err)
				return
			}

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Add("cache-control", "no-cache")

			ctx, _ := context.WithTimeout(req.Context(), 3*time.Second)
			req = req.WithContext(ctx)

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				fmt.Println(err)
				return
			}

			defer res.Body.Close()
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				fmt.Println(err)
				return
			}

			fmt.Println(string(body))
		}()
	}
}
