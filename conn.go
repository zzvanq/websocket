package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
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
const maxFramePayloadLen = 64 * 1024
const (
	statusOpen   = iota + 1
	statusClosed = iota
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

type Conn struct {
	status   int
	isServer bool
	conn     net.Conn
	br       *bufio.Reader
}

func (c *Conn) Close() error {
	err := c.conn.Close()
	if err != nil {
		return err
	}
	c.status = statusClosed
	return nil
}

func (c *Conn) Write(msgType int, data []byte) error {
	if c.status == statusClosed {
		return ErrConnectionClosed
	}

	mask := 0x1
	if c.isServer {
		mask = 0x0
	}

	fn := max(len(data)/maxFramePayloadLen, 1)
	for i := 0; i < fn; i++ {
		l := i * maxFramePayloadLen
		r := min((i+1)*maxFramePayloadLen, len(data))
		payload := data[l:r]

		f := make([]byte, 14+len(payload))

		fin := 0x0
		if i == fn-1 {
			fin = 0x1
		}
		opCode := ContinuationFrame
		if i == 0 {
			opCode = int(msgType)
		}
		f[0] = byte((fin << 7) | opCode)

		payloadLen := len(payload)
		switch {
		case len(payload) > 0xFFFF:
			payloadLen = 127
			binary.BigEndian.PutUint64(f[2:], uint64(len(payload)))
		case len(payload) > 125:
			payloadLen = 126
			binary.BigEndian.PutUint16(f[2:], uint16(len(payload)))
		}

		f[1] = byte((mask << 7) | payloadLen)

		if mask == 0x1 {
			_, err := rand.Read(f[10:14])
			if err != nil {
				panic(err)
			}
			if payloadLen > 0 {
				maskData(data, f[10:14])
				copy(f[14:], data)
			}
		}

		_, err := io.Copy(c.conn, bytes.NewReader(f))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) Read() (*Message, error) {
	if c.status == statusClosed {
		return nil, ErrConnectionClosed
	}

	var (
		recvd  []byte
		opCode byte
	)

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
			c.Write(Pong, frame.Payload)
			continue
		case TextFrame, BinaryFrame:
			if len(recvd) != 0 {
				return nil, errors.New("unexpected frame")
			}
			opCode = frame.OpCode
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
			return &Message{Type: opCode, Data: recvd}, nil
		}

		recvd = append(recvd, frame.Payload...)
	}
}

func (c *Conn) readFrame() (*Frame, error) {
	headers := make([]byte, 14)
	_, err := io.ReadFull(c.br, headers)
	if err != nil {
		return nil, err
	}

	fin := headers[0] & finMask
	// NOTE: must fail if an extension was not negotiated and this bits are not set,
	// but what's the point? (idk) - ignore
	// rsv1 := headers[0] & rsv1Bit
	// rsv2 := headers[0] & rsv2Bit
	// rsv3 := headers[0] & rsv3Bit
	opCode := headers[0] & opCodeMask

	mask := headers[1] & maskBit
	if (mask == 0x1) != c.isServer {
		return nil, errors.New("incorrect MASK bit")
	}

	payloadLen := uint64(headers[1] & payloadLenMask)

	switch payloadLen {
	case 126:
		payloadLen = uint64(binary.BigEndian.Uint16(headers[2:4]))
	case 127:
		payloadLen = uint64(binary.BigEndian.Uint64(headers[2:10]))
	}

	maskKey := headers[10:14]

	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(c.br, payload)
	if err != nil {
		return nil, err
	}

	if mask == 0x1 {
		maskData(payload, maskKey)
	}

	switch opCode {
	case ConnectionClose, Ping, Pong:
		if fin != 0x1 {
			return nil, errors.New("FIN not set on control frames")
		}
		if payloadLen > 125 {
			return nil, errors.New("control frame payload length is too big (max 125)")
		}
	case ContinuationFrame:
		if fin == 0x1 {
			return nil, errors.New("continuation frames must not be final")
		}
	default:
		return nil, errors.New("unknown opcode")
	}

	return &Frame{Fin: fin == 0x1, OpCode: opCode, Payload: payload}, nil
}

func maskData(data []byte, key []byte) {
	// NOTE: i have no idea if loop unrolling is worth it. Just for fun
	i := 0
	for ; i+4 <= len(data); i += 4 {
		data[i] ^= key[0]
		data[i+1] ^= key[1]
		data[i+2] ^= key[2]
		data[i+3] ^= key[3]
	}

	for ; i < len(data); i++ {
		data[i] ^= key[i%4]
	}
}

func getSecAccept(key string) (string, error) {
	if key == "" {
		return "", errors.New("Sec-WebSocket-Key header is empty")
	}
	h := sha1.New()
	_, err := h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
