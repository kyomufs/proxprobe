package emit

import "encoding/json"

// jsonUnmarshal — тонкая обёртка, чтобы тесты не тянули лишний импорт.
func jsonUnmarshal(body []byte, v any) error { return json.Unmarshal(body, v) }
