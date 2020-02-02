package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"github.com/apsdehal/go-logger"
	"github.com/rirush/safeMessages/protocol"
	"github.com/tinylib/msgp/msgp"
	"golang.org/x/crypto/ed25519"
	"net"
	"runtime/debug"
	"strconv"
)

var lastClient = 0

func Listen(listener net.Listener) {
	log, _ := logger.New("listener", 1)
	log.SetLogLevel(defaultLogLevel)
	for {
		conn, err := listener.Accept()
		log.Debugf("New connection from %v", conn.RemoteAddr())
		if err != nil {
			log.Errorf("Server couldn't accept connection: %v", err)
			continue
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Errorf("Cannot cast connection to tls.Conn")
			_ = conn.Close()
			continue
		}
		err = tlsConn.Handshake()
		if err != nil {
			log.Errorf("Handshake failed: %v", err)
			_ = conn.Close()
			continue
		}

		lastClient += 1
		ctx := &ClientContext{Conn: tlsConn}
		go ctx.startHandler()
	}
}

type ClientContext struct {
	Conn                   *tls.Conn
	Encoding               string
	Logger                 *logger.Logger
	ActiveDevice           *Device
	CurrentMessage         []byte
	CurrentChallenge       []byte
	CurrentChallengeDevice *Device
}

func (ctx *ClientContext) startHandler() {
	ctx.Logger, _ = logger.New("handler-"+strconv.Itoa(lastClient), 1)
	ctx.Logger.SetLogLevel(defaultLogLevel)

	defer func() {
		if r := recover(); r != nil {
			header, errBody := protocol.NewError(protocol.ErrInternalServerError, protocol.ErrInternalServerErrorDesc)
			_ = ctx.Reply(header, errBody)
			if s, ok := r.(string); ok {
				if s == "network" || s == "encoding" {
					ctx.Logger.Debug("Error occurred while decoding body, closing the connection")
				} else {
					ctx.Logger.Criticalf("PANIC! %v", r)
					ctx.Logger.Criticalf("Stacktrace:\n%v", string(debug.Stack()))
				}
			} else {
				ctx.Logger.Criticalf("PANIC! %v", r)
				ctx.Logger.Criticalf("Stacktrace:\n%v", string(debug.Stack()))
			}
		}

		//if ctx.ActiveDevice != nil {
		//	ctx.ActiveDevice.SetInactive()
		//}

		ctx.Logger.Debug("Connection is closed")
		_ = ctx.Conn.Close()
	}()

outerLoop:
	for {
		ctx.CurrentMessage = nil
		var size uint16
		err := binary.Read(ctx.Conn, binary.BigEndian, &size)
		if err != nil {
			ctx.Logger.Warningf("Error occurred while reading from client: %v", err)
			break
		}
		ctx.Logger.Debugf("Waiting for %d bytes", size)
		// TODO: Size limiting
		buf := make([]byte, size)
		read := 0
		for read != int(size) {
			_read, err := ctx.Conn.Read(buf[read:])
			read += _read
			ctx.Logger.Debugf("Read %d bytes", _read)
			if err != nil {
				ctx.Logger.Warningf("Error occurred while reading from client: %v", err)
				break outerLoop
			}
		}

		header := protocol.MessageHeader{}
		if ctx.Encoding == "" {
			ctx.Logger.Debug("No encoding set, trying to guess")
			err = json.Unmarshal(buf, &header)
			if err != nil {
				ctx.Logger.Debug("JSON decode failed, moving on")
				ctx.Logger.Debugf("JSON error: %v", err)
				_, err = header.UnmarshalMsg(buf)
				if err != nil {
					ctx.Logger.Debug("MessagePack decode failed, closing the connection")
					ctx.Logger.Debugf("JSON error: %v", err)
					break
				} else {
					ctx.Logger.Debug("Determined that encoding is msgpack")
					ctx.Encoding = "msgpack"
				}
			} else {
				ctx.Logger.Debug("Determined that encoding is json")
				ctx.Encoding = "json"
			}
		} else {
			header, err = ctx.ReadHeader(buf)
			if err != nil {
				ctx.Logger.Debugf("Message decode failed: %v", err)
				header, errBody := protocol.NewError(protocol.ErrDeserializationFailure, protocol.ErrDeserializationFailureDesc)
				err = ctx.Reply(header, errBody)
				if err != nil {
					ctx.Logger.Warningf("Failed writing reply to client: %v", err)
				}
				// On deserialization failure we cannot be sure that connection is clear
				// TODO: Is closing the connection a valid strategy?
				break
			}
		}
		result, clientErr, err := ctx.ProcessMessage(&header)
		if err != nil {
			ctx.Logger.Criticalf("Message processing failed: %v", err)
			header, errBody := protocol.NewError(protocol.ErrInternalServerError, protocol.ErrInternalServerErrorDesc)
			err = ctx.Reply(header, errBody)
			if err != nil {
				ctx.Logger.Warningf("Failed writing reply to client: %v", err)
				break
			}
			continue
		}
		if clientErr != nil {
			header.Type = protocol.TypeError
			err = ctx.Reply(header, clientErr)
			if err != nil {
				ctx.Logger.Warningf("Failed writing reply to client: %v", err)
				break
			}
			continue
		}
		err = ctx.Reply(header, result)
		if err != nil {
			ctx.Logger.Warningf("Failed writing reply to client: %v", err)
			break
		}
	}
}

func (ctx *ClientContext) sendMsgpackReply(header protocol.MessageHeader, body msgp.MarshalSizer) (err error) {
	encodedBody, _ := body.MarshalMsg(nil)
	header.Size = len(encodedBody)
	encodedHeader, _ := header.MarshalMsg(nil)
	var buf []byte
	stream := bytes.NewBuffer(buf)
	_ = binary.Write(stream, binary.BigEndian, uint16(len(encodedHeader)))
	stream.Write(encodedHeader)
	stream.Write(encodedBody)
	_, err = stream.WriteTo(ctx.Conn)
	return
}

func (ctx *ClientContext) sendJSONReply(header protocol.MessageHeader, body interface{}) (err error) {
	bodyBytes, _ := json.Marshal(body)
	header.Size = len(bodyBytes)
	headerBytes, _ := json.Marshal(header)
	var buf []byte
	stream := bytes.NewBuffer(buf)
	_ = binary.Write(stream, binary.BigEndian, uint16(len(headerBytes)))
	stream.Write(headerBytes)
	stream.Write(bodyBytes)
	_, err = stream.WriteTo(ctx.Conn)
	return
}

func (ctx *ClientContext) Reply(header protocol.MessageHeader, body msgp.MarshalSizer) (err error) {
	switch ctx.Encoding {
	case "json":
		err = ctx.sendJSONReply(header, body)
	case "msgpack":
		err = ctx.sendMsgpackReply(header, body)
	default:
		panic("Invalid encoding")
	}
	return
}

func (ctx *ClientContext) ReadHeader(buf []byte) (header protocol.MessageHeader, err error) {
	switch ctx.Encoding {
	case "json":
		err = json.Unmarshal(buf, &header)
	case "msgpack":
		_, err = header.UnmarshalMsg(buf)
	default:
		panic("Invalid encoding")
	}
	return
}

func (ctx *ClientContext) ReadMessage(header protocol.MessageHeader, message msgp.Unmarshaler) {
	buf := make([]byte, header.Size)
	read := 0
	ctx.Logger.Debugf("Reading %d body bytes", header.Size)
	for read != header.Size {
		_read, err := ctx.Conn.Read(buf[read:])
		read += _read
		ctx.Logger.Debugf("Read %d bytes", _read)
		if err != nil {
			ctx.Logger.Warningf("Error occurred while reading from client: %v", err)
			panic("network")
		}
	}
	ctx.CurrentMessage = buf
	switch ctx.Encoding {
	case "json":
		err := json.Unmarshal(buf, message)
		if err != nil {
			ctx.Logger.Warningf("Error occurred while unmarshalling message: %v", err)
			panic("encoding")
		}
	case "msgpack":
		_, err := message.UnmarshalMsg(buf)
		if err != nil {
			ctx.Logger.Warningf("Error occurred while unmarshalling message: %v", err)
			panic("encoding")
		}
	default:
		panic("Invalid encoding")
	}
}

func (ctx *ClientContext) VerifyMessage(header *protocol.MessageHeader, key ed25519.PublicKey) bool {
	if ctx.CurrentMessage == nil {
		panic("Invalid call to verify message: currentMessage is nil")
	}
	if header.Signature == nil {
		return false
	}
	return ed25519.Verify(key, ctx.CurrentMessage, header.Signature)
}

func (ctx *ClientContext) ProcessMessage(header *protocol.MessageHeader) (result msgp.MarshalSizer, clientError *protocol.Error, err error) {
	f, ok := HandlerMap[header.Type]
	if !ok {
		ctx.Logger.Debugf("Client requested unknown method %s", header.Type)
		_header, _clientError := protocol.NewError(protocol.ErrUnknownType, protocol.ErrUnknownTypeDesc)
		*header = _header
		clientError = &_clientError
		return
	}
	result, clientError, err = f(ctx, header)
	return
}
