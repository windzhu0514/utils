package json

import (
	"encoding/json"
	"strings"
)

type FieldValue struct {
	String  string
	Float64 float64
}

func SortByField(jsonStr, field string) error {
	jsonStr = strings.TrimSpace(jsonStr)
	if strings.HasPrefix(jsonStr, "[") { // array
		var m []interface{}
		if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
			return err
		}

		var fieldValues []interface{}
		for i := 0; i < len(m); i++ {
			object := m[i].(map[string]interface{})
			for k, v := range object {
				if k == field {
					fieldValues = append(fieldValues, v)
				}
			}
		}

		var mm []interface{}
		for i := 0; i < len(m); i++ {
			object := m[i].(map[string]interface{})
			mm = append(mm, object)
		}

	} else {
		//var m map[string]interface{}
	}

	return nil
}
