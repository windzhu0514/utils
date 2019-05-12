package main

import (
	"fmt"
	_ "net/http/pprof"
	"net/url"

	"github.com/windzhu0514/go-utils/hihttp/hihttp"
)

func main() {
	hihttp.SetProxy("http://127.0.0.1:8888")
	// req := hihttp.NewRequest(http.MethodGet, "http://www.baidu.com", nil)
	// resp, err := req.Do()
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	//
	// fmt.Println(resp.Body())

	v := url.Values{}
	v.Add("jsonStr", "jsonStr")
	statusCode, resp, err := hihttp.Post("http://47.110.127.250:6600/proxy", v.Encode(), hihttp.PostOption{
		ContentType: hihttp.CTApplicationForm})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(statusCode, string(resp))
}
