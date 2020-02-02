package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/rirush/safeMessages/protocol"
	"github.com/tinylib/msgp/msgp"
	"golang.org/x/crypto/curve25519"
)

type HandlerFunc func(ctx *ClientContext, header *protocol.MessageHeader) (result msgp.MarshalSizer, clientError *protocol.Error, err error)

var HandlerMap map[string]HandlerFunc

func init() {
	HandlerMap = make(map[string]HandlerFunc)
	HandlerMap[protocol.TypeRegister] = RegisterHandler
	HandlerMap[protocol.TypeIntroduceRequest] = IntroduceRequestHandler
	HandlerMap[protocol.TypeSetEncoding] = SetEncodingHandler
	HandlerMap[protocol.TypeIntroduce] = IntroduceHandler
}

func RegisterHandler(ctx *ClientContext, header *protocol.MessageHeader) (result msgp.MarshalSizer, clientError *protocol.Error, err error) {
	message := protocol.Register{}
	ctx.ReadMessage(*header, &message)
	if message.Name == "" || len(message.PublicExchangeKey) != curve25519.PointSize || len(message.PublicSignatureKey) != ed25519.PublicKeySize {
		_header, _clientError := protocol.NewError(protocol.ErrInvalidArgument, protocol.ErrInvalidArgumentDesc)
		*header = _header
		clientError = &_clientError
		return
	}
	if !ctx.VerifyMessage(header, message.PublicSignatureKey) {
		_header, _clientError := protocol.NewError(protocol.ErrInvalidSignature, protocol.ErrInvalidSignatureDesc)
		*header = _header
		clientError = &_clientError
		return
	}

	ent := AllocateUUID("device")
	device := CreateDevice(ent)
	device.Name = message.Name
	device.Description = message.Description
	device.PublicSignatureKey = message.PublicSignatureKey
	device.PublicExchangeKey = message.PublicExchangeKey
	device.Insert()

	*header = protocol.MessageHeader{
		Type: protocol.TypeRegister,
	}
	result = &protocol.RegisterReply{
		Address: ent.Address,
	}
	return
}

func IntroduceRequestHandler(ctx *ClientContext, header *protocol.MessageHeader) (result msgp.MarshalSizer, clientError *protocol.Error, _err error) {
	message := protocol.IntroduceRequest{}
	ctx.ReadMessage(*header, &message)

	dev, err := FindDevice(message.Address)
	if err != nil {
		// If device doesn't exist, we don't want to report the error to client right away
		ctx.CurrentChallengeDevice = nil
	} else {
		ctx.CurrentChallengeDevice = &dev
	}

	ctx.CurrentChallenge = make([]byte, 32)
	_, err = rand.Read(ctx.CurrentChallenge)
	if err != nil {
		_err = err
		return
	}

	result = &protocol.IntroduceRequestReply{
		Challenge: ctx.CurrentChallenge,
	}
	return
}

func SetEncodingHandler(ctx *ClientContext, header *protocol.MessageHeader) (result msgp.MarshalSizer, clientError *protocol.Error, _err error) {
	message := protocol.SetEncoding{}
	ctx.ReadMessage(*header, &message)

	if message.Type != "json" && message.Type != "msgpack" {
		_header, _clientError := protocol.NewError(protocol.ErrInvalidArgument, protocol.ErrInvalidArgumentDesc)
		*header = _header
		clientError = &_clientError
		return
	}
	ctx.Encoding = message.Type
	result = protocol.EmptyReply{}
	return
}

func IntroduceHandler(ctx *ClientContext, header *protocol.MessageHeader) (result msgp.MarshalSizer, clientError *protocol.Error, _err error) {
	message := protocol.Introduce{}
	ctx.ReadMessage(*header, &message)

	defer func() {
		ctx.CurrentChallenge = nil
		ctx.CurrentChallengeDevice = nil
	}()

	if ctx.CurrentChallenge == nil {
		_header, _clientError := protocol.NewError(protocol.ErrNoPendingChallenge, protocol.ErrNoPendingChallengeDesc)
		*header = _header
		clientError = &_clientError
		return
	}
	if ctx.CurrentChallengeDevice == nil {
		_header, _clientError := protocol.NewError(protocol.ErrInvalidAddress, protocol.ErrInvalidAddressDesc)
		*header = _header
		clientError = &_clientError
		return
	}
	if len(header.Signature) != ed25519.SignatureSize || !ctx.VerifyMessage(header, ctx.CurrentChallengeDevice.PublicSignatureKey) {
		_header, _clientError := protocol.NewError(protocol.ErrInvalidSignature, protocol.ErrInvalidSignatureDesc)
		*header = _header
		clientError = &_clientError
		return
	}

	ctx.ActiveDevice = ctx.CurrentChallengeDevice
	result = protocol.IntroduceReply{Name:ctx.ActiveDevice.Name}
	return
}