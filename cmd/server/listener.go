package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"github.com/apsdehal/go-logger"
	"github.com/rirush/safeMessages/protocol"
	"github.com/tinylib/msgp/msgp"
	"net"
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
	Conn *tls.Conn
	Encoding string
	Logger *logger.Logger
}

func (ctx *ClientContext) startHandler() {
	ctx.Logger, _ = logger.New("handler-" + strconv.Itoa(lastClient), 1)
	ctx.Logger.SetLogLevel(defaultLogLevel)

	defer func() {
		if r := recover(); r != nil {
			ctx.Logger.Criticalf("PANIC! %v", r)
		}
	}()

outerLoop:
	for {
		var size uint16
		err := binary.Read(ctx.Conn, binary.BigEndian, &size)
		if err != nil {
			ctx.Logger.Errorf("Error happened: %v", err)
			break
		}
		// TODO: Size limiting
		buf := make([]byte, size)
		read := 0
		for read != int(size) {
			_read, err := ctx.Conn.Read(buf[read:])
			read += _read
			if err != nil {
				ctx.Logger.Errorf("Error occurred while reading from client:", err)
				break outerLoop
			}
		}

		header := protocol.MessageHeader{}
		if ctx.Encoding == "" {
			ctx.Logger.Debug("No encoding set, trying to guess")
			err = json.Unmarshal(buf, header)
			if err != nil {
				ctx.Logger.Debug("JSON decode failed, moving on")
				_, err = header.UnmarshalMsg(buf)
				if err != nil {
					ctx.Logger.Debug("MessagePack decode failed, closing the connection")
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

	ctx.Logger.Debug("Connection is closed")
	_ = ctx.Conn.Close()
}

func (ctx *ClientContext) sendMsgpackReply(header protocol.MessageHeader, body msgp.MarshalSizer) (err error) {
	header.Size = body.Msgsize()
	buf := make([]byte, 2 + header.Msgsize() + body.Msgsize())
	stream := bytes.NewBuffer(buf)
	_ = binary.Write(stream, binary.BigEndian, uint16(header.Msgsize()))
	encodedBytes, _ := header.MarshalMsg(nil)
	stream.Write(encodedBytes)
	encodedBytes, _ = body.MarshalMsg(nil)
	stream.Write(encodedBytes)
	_, err = stream.WriteTo(ctx.Conn)
	return
}

func (ctx *ClientContext) sendJSONReply(header protocol.MessageHeader, body interface{}) (err error) {
	bodyBytes, _ := json.Marshal(body)
	header.Size = len(bodyBytes)
	headerBytes, _ := json.Marshal(header)
	buf := make([]byte, 2 + len(headerBytes) + len(bodyBytes))
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
		return
	case "msgpack":
		_, err = header.UnmarshalMsg(buf)
		return
	default:
		panic("Invalid encoding")
	}
}

func (ctx *ClientContext) ProcessMessage(header *protocol.MessageHeader) (result msgp.MarshalSizer, clientError *protocol.Error, err error) {
	panic("unimplemented")
}
