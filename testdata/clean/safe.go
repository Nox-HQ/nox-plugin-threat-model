package clean

import (
	"encoding/json"
	"io"
	"net/http"
)

// FetchRemoteData performs normal HTTP + JSON handling. Reading a response
// body and json.Unmarshal are everyday operations, not a tampering risk —
// THREAT-002 must NOT fire here.
func FetchRemoteData() (map[string]any, error) {
	resp, err := http.Get("https://example.com/api/data")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
