package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

type Conn struct {
	conn net.Conn
	brw  *bufio.ReadWriter
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func newConn(conn net.Conn, brw *bufio.ReadWriter) *Conn {
	return &Conn{conn, brw}
}

func upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if r.Method != http.MethodGet {
		msg := "Method is not GET"
		http.Error(w, msg, http.StatusMethodNotAllowed)
		return nil, errors.New(msg)
	}

	if !r.ProtoAtLeast(1, 1) {
		msg := "Protocol is not supported"
		http.Error(w, msg, http.StatusUpgradeRequired)
		return nil, errors.New(msg)
	}

	if r.Header.Get("Host") == "" {
		msg := "Host header is not set"
		http.Error(w, msg, http.StatusBadRequest)
		return nil, errors.New(msg)
	}

	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		msg := "Invalid Upgrade header"
		http.Error(w, msg, http.StatusBadRequest)
		return nil, errors.New(msg)
	}

	if strings.EqualFold(r.Header.Get("Connection"), "Upgrade") {
		msg := "Invalid Connection header"
		http.Error(w, msg, http.StatusBadRequest)
		return nil, errors.New(msg)
	}

	secAccept, err := getSecAccept(r.Header.Get("Sec-WebSocket-Key"))
	if err != nil {
		http.Error(w, "Sec-WebSocket-Key header is invalid", http.StatusBadRequest)
		return nil, err
	}

	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		msg := "Unsupported websocket version"
		http.Error(w, msg, http.StatusUpgradeRequired)
		return nil, errors.New(msg)
	}

	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", secAccept)
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return nil, err
	}

	return newConn(conn, brw), nil
}

func getSecAccept(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("Sec-WebSocket-Key header is empty")
	}
	h := sha1.New()
	_, err := h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrade(w, r)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
	})

	http.ListenAndServe(":8080", mux)
}
