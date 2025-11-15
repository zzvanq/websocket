package main

import (
	"errors"
	"net/http"
	"strings"
)

func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
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

	secKey := r.Header.Get("Sec-WebSocket-Key")
	if secKey == "" {
		return nil, errors.New("Sec-WebSocket-Key header is empty")
	}
	secAccept, err := getSecAccept(secKey)
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

	br := brw.Reader
	return &Conn{status: statusOpen, isServer: true, conn: conn, br: br}, nil
}
