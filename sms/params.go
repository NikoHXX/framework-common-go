package sms

import "sort"

// orderedParamValues 优先用显式有序切片；否则按 Params key 字典序取值。
func orderedParamValues(req SendRequest) []string {
	if len(req.ParamValues) > 0 {
		return req.ParamValues
	}
	if len(req.Params) == 0 {
		return nil
	}
	keys := make([]string, 0, len(req.Params))
	for k := range req.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, req.Params[k])
	}
	return out
}
