package mitigate

import "encoding/json"

func jsonMarshal(v any) []byte {
	b, _ := json.MarshalIndent(v, "", " ")
	return append(b, '\n')
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
