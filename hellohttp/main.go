package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/windzhu0514/utils/httpclient/internal"
)

func main() {
	for i := 0; i < 10; i++ {
		go func() {
			fmt.Println(time.Now().String())
			req := internal.Get("https://www.baidu.com")
			_, err := req.String()
			if err != nil {
				fmt.Printf("请求失败:%s\n", err.Error())
			} else {
				fmt.Println("请求成功")
			}

			time.Sleep(time.Second * 15)
		}()
	}

	fmt.Println(http.ListenAndServe(":6060", nil))
}
