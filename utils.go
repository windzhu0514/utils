package utils

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

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
