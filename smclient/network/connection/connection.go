package connection

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"strings"
)

type Conn struct {
	conn *tls.Conn
	reader *bufio.Reader
}

func Dial(address string) (Conn, error) {
	c := Conn{}
	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return c, err
}

func MakePacket(code pb.OperationCode, body proto.Message) (pb.Packet, error) {
	encodedBody, err := proto.Marshal(body)
	if err != nil {
		return pb.Packet{}, err
	}
	packet := pb.Packet{
		Data: encodedBody,
		Code: code,
	}
	return packet, nil
}

func SignPacket(key ed25519.PrivateKey, packet *pb.Packet) {
	packet.Signature = ed25519.Sign(key, packet.Data)
}

func (c *Conn) SendPacket(packet *pb.Packet) error {
	data, err := proto.Marshal(packet)
	if err != nil {
		return err
	}
	buf := make([]byte, 11)
	n := binary.PutUvarint(buf, uint64(len(data)))
	_, err = c.conn.Write(buf[:n])
	if err != nil {
		return err
	}
	_, err = c.conn.Write(data)
	return err
}

func (c *Conn) ReadReply() (pb.Reply, error) {
	size, err := binary.ReadUvarint(c.reader)
	if err != nil {
		return pb.Reply{}, err
	}
	buf := make([]byte, size)
	_, err = io.ReadFull(c.reader, buf)
	if err != nil {
		return pb.Reply{}, err
	}
	reply := pb.Reply{}
	err = proto.Unmarshal(buf, &reply)
	return reply, err
}

func (c *Conn) ReadEvent() (pb.Event, error) {
	size, err := binary.ReadUvarint(c.reader)
	if err != nil {
		return pb.Event{}, err
	}
	buf := make([]byte, size)
	_, err = io.ReadFull(c.reader, buf)
	if err != nil {
		return pb.Event{}, err
	}
	event := pb.Event{}
	err = proto.Unmarshal(buf, &event)
	return event, err
}

func DecodeReply(reply pb.Reply, destination proto.Message) (proto.Message, *pb.Error, error) {
	switch reply.Status.(type) {
	case *pb.Reply_Result:
		result := reply.Status.(*pb.Reply_Result)
		err := proto.Unmarshal(result.Result, destination)
		return destination, nil, err
	case *pb.Reply_Error:
		result := reply.Status.(*pb.Reply_Error)
		return nil, result.Error, nil
	}
	return nil, nil, nil
}

func (c *Conn) Register(name string, publicKey ed25519.PublicKey) (*uuid.UUID, *pb.Error, error) {
	packet, err := MakePacket(pb.OperationCode_REGISTER_DEVICE, &pb.RegisterDevice{Name: name, SignatureKey: publicKey})
	if err != nil {
		return nil, nil, err
	}
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, nil, err
	}
	reply, err := c.ReadReply()
	if err != nil {
		return nil, nil, err
	}
	registerReply := pb.RegisterDeviceReply{}
	r, e, err := DecodeReply(reply, &registerReply)
	if err != nil {
		return nil, nil, err
	}
	if r == nil {
		return nil, e, nil
	}
	id, _ := uuid.FromBytes(registerReply.Address)
	return &id, nil, nil
}

func (c *Conn) Authorize(address uuid.UUID, privateKey ed25519.PrivateKey) (*pb.Error, error) {
	packet, err := MakePacket(pb.OperationCode_GENERATE_CHALLENGE, &pb.GenerateChallenge{Address:address[:]})
	if err != nil {
		return nil, err
	}
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, err
	}
	reply, err := c.ReadReply()
	if err != nil {
		return nil, err
	}
	challengeReply := pb.GenerateChallengeReply{}
	_, e, err := DecodeReply(reply, &challengeReply)
	if err != nil {
		return nil, err
	}
	if e != nil {
		return e, err
	}
	bytes := challengeReply.Challenge

	packet, err = MakePacket(pb.OperationCode_AUTHORIZE, &pb.Authorize{Challenge: bytes})
	if err != nil {
		return nil, err
	}
	SignPacket(privateKey, &packet)
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, err
	}
	reply, err = c.ReadReply()
	if err != nil {
		return nil, err
	}
	authorizeReply := pb.AuthorizeReply{}
	_, e, err = DecodeReply(reply, &authorizeReply)
	if err != nil {
		return nil, err
	}
	if e != nil {
		return e, nil
	}
	return nil, nil
}

type IdentityReply struct {
	Address uuid.UUID
	Key []byte
}

func DeriveKey(username, password string) []byte {
	return pbkdf2.Key([]byte(password), []byte(strings.ToLower(username)), 100000, 16, sha256.New)
}

func (c *Conn) RegisterIdentity(username, name string, signatureKey ed25519.PublicKey, privateSignatureKey ed25519.PrivateKey, exchangeKey, privateExchangeKey []byte, password string) (*IdentityReply, *pb.Error, error) {
	key := DeriveKey(username, password)
	verificationHash := sha256.Sum256(key)
	cp, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	g := cipher.NewCBCEncrypter(cp, iv)
	encryptedSignatureKey := make([]byte, len(privateSignatureKey))
	encryptedExchangeKey := make([]byte, 32)
	g.CryptBlocks(encryptedSignatureKey, privateSignatureKey)
	g.CryptBlocks(encryptedExchangeKey, privateExchangeKey[:])
	packet, err := MakePacket(pb.OperationCode_REGISTER_IDENTITY, &pb.RegisterIdentity{
		Name:                  name,
		Username:              username,
		SignatureKey:          signatureKey,
		EncryptedSignatureKey: encryptedSignatureKey,
		ExchangeKey:           exchangeKey[:],
		EncryptedExchangeKey:  encryptedExchangeKey,
		VerificationHash:      verificationHash[:],
	})
	if err != nil {
		return nil, nil, err
	}
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, nil, err
	}
	reply, err := c.ReadReply()
	if err != nil {
		return nil, nil, err
	}
	identityReply := pb.RegisterIdentityReply{}
	_, e, err := DecodeReply(reply, &identityReply)
	if err != nil {
		return nil, nil, err
	}
	if e != nil {
		return nil, e, nil
	}
	address, _ := uuid.FromBytes(identityReply.Address)
	return &IdentityReply{Address:address, Key: key}, nil, nil
}

type LinkIdentityReply struct {
	Address uuid.UUID
	SignatureKey ed25519.PrivateKey
	ExchangeKey []byte
	EncryptionKey []byte
}

func (c *Conn) LinkIdentity(username, password string) (*LinkIdentityReply, *pb.Error, error) {
	key := DeriveKey(username, password)
	verificationHash := sha256.Sum256(key)
	packet, err := MakePacket(pb.OperationCode_LINK_IDENTITY, &pb.LinkIdentity{Username: username, VerificationHash: verificationHash[:]})
	if err != nil {
		return nil, nil, err
	}
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, nil, err
	}
	reply, err := c.ReadReply()
	if err != nil {
		return nil, nil, err
	}
	linkReply := &pb.LinkIdentityReply{}
	_, e, err := DecodeReply(reply, linkReply)
	if err != nil {
		return nil, nil, err
	}
	if e != nil {
		return nil, e, nil
	}
	address, _ := uuid.FromBytes(linkReply.Address)
	result := &LinkIdentityReply{
		Address: address,
		SignatureKey: make([]byte, 64),
		ExchangeKey: make([]byte, 32),
		EncryptionKey: key,
	}
	cp, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	g := cipher.NewCBCDecrypter(cp, iv)
	g.CryptBlocks(result.SignatureKey, linkReply.EncryptedSignatureKey)
	g.CryptBlocks(result.ExchangeKey, linkReply.EncryptedExchangeKey)
	return result, nil, nil
}

type Identity struct {
	Address uuid.UUID
	Username string
	Name string
	SignatureKey ed25519.PublicKey
	ExchangeKey []byte
}

func (c *Conn) QueryIdentity(username string) (*Identity, *pb.Error, error) {
	packet, err := MakePacket(pb.OperationCode_QUERY_IDENTITIES, &pb.QueryIdentities{Query:&pb.QueryIdentities_Username{Username:username}})
	if err != nil {
		return nil, nil, err
	}
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, nil, err
	}
	reply, err := c.ReadReply()
	if err != nil {
		return nil, nil, err
	}
	identity := &pb.QueryIdentitiesReply{}
	_, e, err := DecodeReply(reply, identity)
	if err != nil {
		return nil, nil, err
	}
	if e != nil {
		return nil, e, nil
	}
	if len(identity.Identities) == 0 {
		return nil, nil, nil
	}
	address, _ := uuid.FromBytes(identity.Identities[0].Address)
	return &Identity{
		Address:      address,
		Username:     identity.Identities[0].Username,
		Name:         identity.Identities[0].Name,
		SignatureKey: identity.Identities[0].SignatureKey,
		ExchangeKey:  identity.Identities[0].ExchangeKey,
	}, nil, nil
}

func (c *Conn) QueryIdentityByAddress(address uuid.UUID) (*Identity, *pb.Error, error) {
	packet, err := MakePacket(pb.OperationCode_QUERY_IDENTITIES, &pb.QueryIdentities{Query:&pb.QueryIdentities_Address{Address: address[:]}})
	if err != nil {
		return nil, nil, err
	}
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, nil, err
	}
	reply, err := c.ReadReply()
	if err != nil {
		return nil, nil, err
	}
	identity := &pb.QueryIdentitiesReply{}
	_, e, err := DecodeReply(reply, identity)
	if err != nil {
		return nil, nil, err
	}
	if e != nil {
		return nil, e, nil
	}
	if len(identity.Identities) == 0 {
		return nil, nil, nil
	}
	return &Identity{
		Address:      address,
		Username:     identity.Identities[0].Username,
		Name:         identity.Identities[0].Name,
		SignatureKey: identity.Identities[0].SignatureKey,
		ExchangeKey:  identity.Identities[0].ExchangeKey,
	}, nil, nil
}

func (c *Conn) SendMessage(dest uuid.UUID, src uuid.UUID, text string, secret []byte, signatureKey ed25519.PrivateKey) (*pb.Error, error) {
	packet, err := MakePacket(pb.OperationCode_SEND_MESSAGE, &pb.Message{Content:&pb.Message_Text{Text: &pb.Message_TextMessage{Text:text}}})
	if err != nil {
		return nil, err
	}
	cp, _ := aes.NewCipher(secret)
	gcm, _ := cipher.NewGCM(cp)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	packet.Data = gcm.Seal(nonce, nonce, packet.Data, nil)
	packet.Source = src[:]
	packet.Destination = dest[:]
	SignPacket(signatureKey, &packet)
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, err
	}
	reply, err := c.ReadReply()
	if err != nil {
		return nil, err
	}
	data := &pb.SendMessageReply{}
	_, e, err := DecodeReply(reply, data)
	return e, err
}

type Message struct {
	Sender uuid.UUID
	Data []byte
	Signature []byte
}

func (c *Conn) ReceiveMessages(receiver uuid.UUID) (<-chan Message, error) {
	packet, err := MakePacket(pb.OperationCode_LISTEN_FOR_EVENTS, &pb.ListenForEvents{})
	if err != nil {
		return nil, err
	}
	packet.Source = receiver[:]
	err = c.SendPacket(&packet)
	if err != nil {
		return nil, err
	}
	messages := make(chan Message, 100)
	go func() {
		for {
			event, err := c.ReadEvent()
			if err != nil {
				close(messages)
				return
			}
			msg := &pb.EncapsulatedMessage{}
			_ = proto.Unmarshal(event.Data, msg)
			id, _ := uuid.FromBytes(msg.Sender)
			messages <- Message{
				Sender: id,
				Data:   msg.Message,
				Signature: msg.Signature,
			}
		}
	}()
	return messages, nil
}