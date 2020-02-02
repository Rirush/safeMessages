package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/rirush/safeMessages/protocol"
	"github.com/tinylib/msgp/msgp"
	"golang.org/x/crypto/curve25519"
	"io/ioutil"
)

type Client struct {
	conn *tls.Conn
	publicSignatureKey ed25519.PublicKey
	privateSignatureKey ed25519.PrivateKey
	publicExchangeKey []byte
	privateExchangeKey []byte
	encoding string
}

type DeviceDescriptor struct {
	UUID uuid.UUID
	Name string
	Description string
	PublicSignatureKey ed25519.PublicKey
	PrivateSignatureKey ed25519.PrivateKey
	PublicExchangeKey []byte
	PrivateExchangeKey []byte
}

func (d *DeviceDescriptor) SaveToFilesystem(path string) {
	data, _ := json.Marshal(d)
	err := ioutil.WriteFile(path, data, 0700)
	if err != nil {
		panic(err)
	}
}

func LoadDeviceDescriptor(path string) (dev DeviceDescriptor) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(data, &dev)
	if err != nil {
		panic(err)
	}
	return
}

func CreateNewDevice(name string) (dev DeviceDescriptor) {
	dev.Name = name
	dev.PublicSignatureKey, dev.PrivateSignatureKey, _ = ed25519.GenerateKey(nil)
	dev.PrivateExchangeKey = make([]byte, 32)
	_, _ = rand.Read(dev.PrivateExchangeKey)
	dev.PublicExchangeKey, _ = curve25519.X25519(dev.PrivateExchangeKey, curve25519.Basepoint)
	return
}

func NewClient(conn *tls.Conn, dev DeviceDescriptor) Client {
	return Client{
		conn:                conn,
		publicSignatureKey:  dev.PublicSignatureKey,
		privateSignatureKey: dev.PrivateSignatureKey,
		publicExchangeKey:   dev.PublicExchangeKey,
		privateExchangeKey:  dev.PrivateExchangeKey,
		encoding:            "msgpack",
	}
}

func (c *Client) EncodeMessage(message msgp.Marshaler) (data []byte, err error) {
	switch c.encoding {
	case "json":
		data, err = json.Marshal(message)
	case "msgpack":
		data, err = message.MarshalMsg(nil)
	default:
		panic("invalid encoding")
	}
	return
}

func (c *Client) DecodeMessage(data []byte, result msgp.Unmarshaler) (err error) {
	switch c.encoding {
	case "json":
		err = json.Unmarshal(data, result)
	case "msgpack":
		_, err = result.UnmarshalMsg(data)
	default:
		panic("invalid encoding")
	}
	return
}

func (c *Client) ReadBytes(buf []byte, size int) error {
	read, err := c.conn.Read(buf)
	if err != nil {
		return err
	}
	if read != size {
		_read, err := c.conn.Read(buf[read:])
		if err != nil {
			return err
		}
		read += _read
	}
	return err
}

func (c *Client) Invoke(method string, arguments msgp.Marshaler, sign bool, result msgp.Unmarshaler) (serverErr *protocol.Error, err error) {
	var bodyBytes, headerBytes []byte
	header := protocol.MessageHeader{
		Type:        method,
		Signature:   nil,
		Source:      [16]byte{},
		Destination: [16]byte{},
		Size:        0,
	}

	bodyBytes, _ = c.EncodeMessage(arguments)
	header.Size = len(bodyBytes)
	if sign {
		header.Signature = ed25519.Sign(c.privateSignatureKey, bodyBytes)
	}
	headerBytes, _ = c.EncodeMessage(&header)
	err = binary.Write(c.conn, binary.BigEndian, uint16(len(headerBytes)))
	if err != nil {
		return
	}
	_, err = c.conn.Write(headerBytes)
	if err != nil {
		return
	}
	_, err = c.conn.Write(bodyBytes)
	if err != nil {
		return
	}


	var size uint16
	err = binary.Read(c.conn, binary.BigEndian, &size)
	buf := make([]byte, size)
	err = c.ReadBytes(buf, int(size))

	header = protocol.MessageHeader{}

	err = c.DecodeMessage(buf, &header)
	if err != nil {
		return
	}

	buf = make([]byte, header.Size)
	err = c.ReadBytes(buf, header.Size)
	if err != nil {
		return
	}
	switch header.Type {
	case method:
		err = c.DecodeMessage(buf, result)
	case "error":
		serverErr = &protocol.Error{}
		err = c.DecodeMessage(buf, serverErr)
	default:
		err = errors.New("method type mismatch")
	}
	return
}

func main() {
	conn, err := tls.Dial("tcp", ":9000", &tls.Config{
		ServerName: "localhost",
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	conn.Handshake()
	dev := LoadDeviceDescriptor("owo.json")
	client := NewClient(conn, dev)

	fmt.Println([16]byte(dev.UUID))

	r1 := protocol.IntroduceRequestReply{}
	sErr, err := client.Invoke(protocol.TypeIntroduceRequest, &protocol.IntroduceRequest{Address: dev.UUID}, false, &r1)
	if err != nil {
		fmt.Println("damn:", err)
		return
	}
	if sErr != nil {
		fmt.Println("fuck:", sErr.Description)
		return
	}

	r2 := protocol.IntroduceReply{}
	sErr, err = client.Invoke(protocol.TypeIntroduce, &protocol.Introduce{Challenge: r1.Challenge}, true, &r2)
	if err != nil {
		fmt.Println("damn:", err)
		return
	}
	if sErr != nil {
		fmt.Println("fuck:", sErr.Description)
		return
	}
	fmt.Println("We are", r2.Name)
}