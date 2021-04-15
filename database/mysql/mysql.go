package mysql

import (
	"fmt"
	"reflect"
)

func dbFields(rv reflect.Value) []string {
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	rt := rv.Type()

	var fields []string
	if rv.Kind() == reflect.Struct {
		for i := 0; i < rv.NumField(); i++ {
			sf := rv.Field(i)
			if sf.Kind() == reflect.Struct {
				fields = append(fields, dbFields(sf)...)
				continue
			}

			tagName := rt.Field(i).Tag.Get("db")
			if tagName != "" {
				fields = append(fields, tagName)
			}
		}
		return fields
	}

	if rv.Kind() == reflect.Map {
		for _, key := range rv.MapKeys() {
			fields = append(fields, key.String())
		}
		return fields
	}

	panic(fmt.Errorf("dbFields requires a struct or a map, found: %s", rv.Kind().String()))
}
