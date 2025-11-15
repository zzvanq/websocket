package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
)

func Dial(ctx context.Context, urlStr string, header http.Header) (*Conn, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	default:
		return nil, errors.New("scheme is not supported")
	}

	secKey, err := generateSecKey()
	if err != nil {
		return nil, err
	}

	req := http.Request{
		Method: http.MethodGet,
		URL:    u,
		Host:   u.Host,
		Header: header,
	}
	req.WithContext(ctx)

	req.Header["Upgrade"] = []string{"websocket"}
	req.Header["Connection"] = []string{"Upgrade"}
	req.Header["Sec-WebSocket-Key"] = []string{secKey}
	req.Header["Sec-WebSocket-Version"] = []string{"13"}

	netDialer := net.Dialer{}
	if deadline, ok := ctx.Deadline(); ok {
		netDialer.Deadline = deadline
	}
	netConn, err := netDialer.Dial(u.Scheme, u.Host)

	defer func() {
		if err != nil {
			netConn.Close()
		}
	}()

	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(netConn)
	conn := &Conn{status: statusOpen, isServer: false, conn: netConn, br: br}

	if err := req.Write(netConn); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(br, &req)
	if err != nil {
		return nil, err
	}

	secAccept, err := getSecAccept(secKey)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols ||
		resp.Header.Get("Upgrade") == "" ||
		resp.Header.Get("Connection") == "" ||
		resp.Header.Get("Sec-WebSocket-Accept") != secAccept {
		return nil, errors.New("handshake failed")
	}

	return conn, nil
}

func generateSecKey() (string, error) {
	k := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

