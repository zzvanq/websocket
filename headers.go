package main

import (
	"crypto/sha1"
	"encoding/base64"
)

func getSecAccept(key string) (string, error) {
	h := sha1.New()
	_, err := h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
