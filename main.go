package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

var ErrConnectionClosed = errors.New("connection was closed")

const (
	// rsv1Mask       = 1 << 6
	// rsv2Mask       = 1 << 5
	// rsv3Mask       = 1 << 4
	finMask        = 1 << 7
	opCodeMask     = 0x0F
	maskBit        = 1 << 7
	payloadLenMask = 0x7F
)

const (
	ContinuationFrame = 0x0
	TextFrame         = 0x1
	BinaryFrame       = 0x2
	ConnectionClose   = 0x8
	Ping              = 0x9
	Pong              = 0xA
)

type Frame struct {
	OpCode  byte
	Fin     bool
	Payload []byte
}

type Message struct {
	Type byte
	Data []byte
}

const (
	statusOpen   = iota + 126
	statusClosed = iota
)

type Conn struct {
	status   int
	isServer bool
	conn     net.Conn
	brw      bufio.ReadWriter
}

func (c *Conn) Close() error {
	err := c.conn.Close()
	if err != nil {
		return err
	}
	c.status = statusClosed
	return nil
}

func (c *Conn) Read() (*Message, error) {
	if c.status == statusClosed {
		return nil, ErrConnectionClosed
	}

	var recvd []byte

	for {
		frame, err := c.readFrame()
		if err != nil {
			return nil, err
		}

		switch frame.OpCode {
		case ConnectionClose:
			c.status = statusClosed
			return &Message{Type: frame.OpCode, Data: frame.Payload}, ErrConnectionClosed
		case Pong:
			continue
		case Ping:
			// TODO: send pong
			continue
		case TextFrame, BinaryFrame:
			if len(recvd) != 0 {
				return nil, errors.New("unexpected frame")
			}
		case ContinuationFrame:
			if len(recvd) == 0 {
				return nil, errors.New("unexpected frame")
			}
		}

		if frame.Fin {
			if len(recvd) == 0 {
				return &Message{Type: frame.OpCode, Data: frame.Payload}, nil
			}

			recvd = append(recvd, frame.Payload...)
			return &Message{Type: frame.OpCode, Data: recvd}, nil
		}

		recvd = append(recvd, frame.Payload...)
	}
}

func (c *Conn) readFrame() (*Frame, error) {
	headers := make([]byte, 14)
	_, err := io.ReadFull(c.brw, headers)
	if err != nil {
		return nil, err
	}

	isFin := (headers[0] & finMask) == 1
	// NOTE: must fail if an extension was not negotiated and this bits are not set,
	// but what's the point? (idk) - ignore
	// rsv1 := headers[0] & rsv1Bit
	// rsv2 := headers[0] & rsv2Bit
	// rsv3 := headers[0] & rsv3Bit
	opCode := headers[0] & opCodeMask

	isMasked := (headers[1] & maskBit) == 1
	if isMasked != c.isServer {
		return nil, errors.New("incorrect MASK bit")
	}

	payloadLen := int(headers[1] & payloadLenMask)

	switch payloadLen {
	case 126:
		payloadLen = int(binary.BigEndian.Uint16(headers[2:4]))
	case 127:
		payloadLen = int(binary.BigEndian.Uint64(headers[2:10]))
	}

	maskKey := headers[10:14]

	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(c.brw, payload)
	if err != nil {
		return nil, err
	}

	if isMasked {
		// NOTE: i have no idea if loop unrolling is worth it. Just for fun
		i := 0
		for ; i+4 <= len(payload); i += 4 {
			payload[i] ^= maskKey[0]
			payload[i+1] ^= maskKey[1]
			payload[i+2] ^= maskKey[2]
			payload[i+3] ^= maskKey[3]
		}

		for ; i < len(payload); i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	switch opCode {
	case ConnectionClose, Ping, Pong:
		if !isFin {
			return nil, errors.New("FIN not set on control frames")
		}
		if payloadLen > 125 {
			return nil, errors.New("control frame payload length is too big (max 125)")
		}
	case ContinuationFrame:
		if isFin {
			return nil, errors.New("continuation frames must not be final")
		}
	default:
		return nil, errors.New("unknown opcode")
	}

	return &Frame{Fin: isFin, OpCode: opCode, Payload: payload}, nil
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
