package websocket

import (
	"bufio"
	"bytes"
	"crypto/rand"
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
const (
	frameHeadersLen    = 14
	maxFramePayloadLen = (10 * 1460) - frameHeadersLen
)
const (
	statusOpen = iota
	statusClosed
)

type Frame struct {
	OpCode  int
	Fin     bool
	Payload []byte
}

type Message struct {
	Type int
	Data []byte
}

type Conn struct {
	status   int
	isServer bool
	conn     net.Conn
	br       *bufio.Reader
}

func (c *Conn) Close() error {
	if c.status == statusClosed {
		return ErrConnectionClosed
	}
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

		f := make([]byte, frameHeadersLen+len(payload))

		fin := 0x0
		if i == fn-1 {
			fin = 0x1
		}
		opCode := ContinuationFrame
		if i == 0 {
			opCode = msgType
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

		copy(f[frameHeadersLen:], payload)
		if mask == 0x1 {
			if _, err := rand.Read(f[10:14]); err != nil {
				panic(err)
			}
			if payloadLen > 0 {
				maskData(f[frameHeadersLen:], f[10:14])
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
		opCode int
	)

	for {
		frame, err := c.readFrame()
		if err != nil {
			return nil, err
		}

		switch frame.OpCode {
		case ConnectionClose:
			c.Write(ConnectionClose, frame.Payload)
			c.Close()
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
	headers := make([]byte, frameHeadersLen)
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
	opCode := int(headers[0] & opCodeMask)

	mask := headers[1] & maskBit
	if (mask != 0x0) != c.isServer {
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

	if mask != 0x0 {
		maskData(payload, maskKey)
	}

	switch opCode {
	case ConnectionClose, Ping, Pong:
		if fin == 0x0 {
			return nil, errors.New("FIN not set on control frames")
		}
		if payloadLen > 125 {
			return nil, errors.New("control frame payload length is too big (max 125)")
		}
	case ContinuationFrame, TextFrame, BinaryFrame:
	default:
		return nil, errors.New("unknown opcode")
	}

	return &Frame{Fin: fin != 0x0, OpCode: opCode, Payload: payload}, nil
}

func maskData(data []byte, key []byte) {
	ukey32 := binary.LittleEndian.Uint32(key)
	ukey := uint64(ukey32)<<32 | uint64(ukey32)

	i := 0
	for ; i+8 <= len(data); i += 8 {
		d := data[i : i+8]
		chunk := binary.LittleEndian.Uint64(d) ^ ukey
		binary.LittleEndian.PutUint64(d, chunk)
	}

	for ; i < len(data); i++ {
		data[i] ^= key[i%4]
	}
}
