package main

import "fmt"

func mutableNestedSlice(obj map[interface{}]interface{}, fields ...string) ([]interface{}, bool, error) {
	val, found, err := nestedFieldNoCopy(obj, fields...)
	if !found || err != nil {
		return nil, found, err
	}
	retVal, ok := val.([]interface{})
	if !ok {
		return nil, false, fmt.Errorf("could not convert to []interface{}")
	}
	return retVal, true, nil
}

func nestedFieldNoCopy(obj map[interface{}]interface{}, fields ...string) (interface{}, bool, error) {
	var val interface{} = obj

	for _, field := range fields {
		if val == nil {
			return nil, false, nil
		}
		if m, ok := val.(map[interface{}]interface{}); ok {
			val, ok = m[field]
			if !ok {
				return nil, false, nil
			}
		} else {
			return nil, false, fmt.Errorf("%v is of the type %T, expected map[string]interface{}", val, val)
		}
	}
	return val, true, nil
}

// pulled from k8s.io/apimachinery/pkg/apis/meta/v1/unstructured
func removeNestedField(obj map[interface{}]interface{}, fields ...string) {
	m := obj
	for _, field := range fields[:len(fields)-1] {
		if x, ok := m[field].(map[interface{}]interface{}); ok {
			m = x
		} else {
			return
		}
	}
	delete(m, fields[len(fields)-1])
}
