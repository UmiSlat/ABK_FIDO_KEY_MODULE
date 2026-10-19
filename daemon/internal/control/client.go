package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// Call makes one bounded, half-closed request. The server waits for EOF so a
// command cannot hide trailing data after a valid JSON object.
func Call(ctx context.Context, path string, req Request) (json.RawMessage, error) {
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(45 * time.Second)
	if when, ok := ctx.Deadline(); ok && when.Before(deadline) {
		deadline = when
	}
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err = json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	if err = c.(*net.UnixConn).CloseWrite(); err != nil {
		return nil, err
	}
	var resp struct {
		OK    bool            `json:"ok"`
		Error string          `json:"error"`
		Data  json.RawMessage `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(c, MaxRequest+1)).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	if len(resp.Data) == 0 {
		return json.RawMessage(`null`), nil
	}
	return resp.Data, nil
}
