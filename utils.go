package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"text/scanner"
	"unsafe"
)

// FormatJSONStr format no-stand json str
func FormatJSONStr(str string) (string, error) {
	replacer := strings.NewReplacer("\t", "", "\n", "", "\v", "", "\f", "", "\r", "", " ", "", "'", "\"")
	str = replacer.Replace(str)

	var s scanner.Scanner
	s.Init(strings.NewReader(str))

	retStr := ""
	for s.Scan() != scanner.EOF {
		token := s.TokenText()

		if s.Peek() == ':' {
			if !strings.HasPrefix(token, "\"") {
				token = "\"" + token
			}
			if !strings.HasSuffix(token, "\"") {
				token += "\""
			}
		}

		retStr += token
	}

	return retStr, nil
}

// EqualFloat64 比较float64 f1 f2可以是字符串或者float64
func EqualFloat64(f1 interface{}, f2 interface{}) (int, error) {

	ff1, err := parseFloat64(f1)
	if err != nil {
		errMsg := fmt.Sprintf("parseFloat64 parse %v error:"+err.Error()+"\n", f1)
		return 0, errors.New(errMsg)
	}
	ff2, err := parseFloat64(f2)
	if err != nil {
		errMsg := fmt.Sprintf("parseFloat64 parse %v error:"+err.Error()+"\n", f2)
		return 0, errors.New(errMsg)
	}

	if ff1-ff2 > 0.0 {
		return 1, nil
	} else if ff1-ff2 < 0.0 {
		return -1, nil
	} else {
		return 0, nil
	}
}

func parseFloat64(f interface{}) (float64, error) {
	var ff float64

	switch f.(type) {
	case float64:
		ff = f.(float64)
	case float32:
		ff = float64(f.(float32))
	case string:
		v, err := strconv.ParseFloat(f.(string), 64)
		if err != nil {
			return 0.0, err
		}
		ff = v
	case int:
		ff = float64(f.(int))
	default:
		errMsg := fmt.Sprintf("%v:type is %v can't convert to float64", f, reflect.TypeOf(f))
		return 0.0, errors.New(errMsg)
	}

	return ff, nil
}

// 从source里随机字符生成出长度为n的字符串
func RandStringN(n int, source string) (str string) {
	len := len(source)
	if len == 0 {
		return
	}

	for i := 0; i < n; i++ {
		str += string(source[rand.Intn(len)])
	}

	return
}

// 字符串和byte互转 无copy 无垃圾回收
func s2b(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}
func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
