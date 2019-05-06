package main

import (
	"fmt"
	_ "net/http/pprof"

	"github.com/windzhu0514/utils/hihttp/hihttp"
	"github.com/windzhu0514/utils/httpclient/httpclient"
)

func main() {
	_, resp, err := hihttp.Get("http://www.baidu.com")
	if err != nil {
		fmt.Printf("请求失败:%s\n", err.Error())
	} else {
		fmt.Println("resp:" + string(resp))
	}
	req := httpclient.Get("https://www.baidu.com")
	resp2, err := req.String()
	if err != nil {
		fmt.Printf("请求失败:%s\n", err.Error())
	} else {
		fmt.Println("resp:" + string(resp2))
	}
}