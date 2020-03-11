package handler

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/database"
	"github.com/Rirush/safeMessages/smserver/event"
	"github.com/google/uuid"
)

func RegisterDevice(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	registrationData := pb.RegisterDevice{}
	err := DecodeMessage(message, &registrationData)
	if err != nil {
		// TODO: unmarshal error
		return protocol.ErrUnknownFunction, nil
	}
	if len(registrationData.SignatureKey) != ed25519.PublicKeySize || registrationData.Name == "" {
		// TODO: argument error
		return protocol.ErrUnknownFunction, nil
	}
	dev := database.Device{
		Key:         registrationData.SignatureKey,
		Name:        registrationData.Name,
		Description: registrationData.Description,
	}
	err = dev.Insert()
	if err != nil {
		return pb.Reply{}, err
	}
	return protocol.NewReply(&pb.RegisterDeviceReply{Address: dev.Address[:]}), nil
}

func GenerateChallenge(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	targetData := pb.GenerateChallenge{}
	err := DecodeMessage(message, &targetData)
	if err != nil {
		// TODO: unmarshal error
		return protocol.ErrUnknownFunction, nil
	}
	if len(targetData.Address) != 16 {
		// TODO: argument error
		return protocol.ErrUnknownFunction, nil
	}
	deviceAddress, _ := uuid.FromBytes(targetData.Address)
	device := database.Device{}
	err = device.FindByAddress(deviceAddress)
	if err != nil {
		// TODO: invalid address error
		return protocol.ErrUnknownFunction, nil
	}
	bytes := make([]byte, 32)
	_, err = rand.Read(bytes)
	if err != nil {
		// TODO: internal server error
		return protocol.ErrUnknownFunction, nil
	}
	session.PendingChallenge = bytes
	session.User = &device
	return protocol.NewReply(&pb.GenerateChallengeReply{Challenge:bytes}), nil
}

func Authorize(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	authorizeData := pb.Authorize{}
	err := DecodeMessage(message, &authorizeData)
	if err != nil {
		// TODO: decode error
		return protocol.ErrUnknownFunction, nil
	}
	if session.Authenticated {
		// TODO: already authorized
		return protocol.ErrUnknownFunction, nil
	}
	if session.User == nil || len(session.PendingChallenge) == 0 {
		// TODO: no pending authorization
		return protocol.ErrUnknownFunction, nil
	}
	if !protocol.CompareBytes(authorizeData.Challenge, session.PendingChallenge) {
		// TODO: invalid challenge error
		return protocol.ErrUnknownFunction, nil
	}
	if !protocol.VerifySignature(message, session.User.Key) {
		// TODO: invalid signature error
		return protocol.ErrUnknownFunction, nil
	}
	session.Authenticated = true
	session.LinkedIdentities, err = session.User.ListLinkedIdentities()
	if err != nil {
		// TODO: internal server error
		return protocol.ErrUnknownFunction, nil
	}
	return protocol.NewReply(&pb.AuthorizeReply{Name:session.User.Name}), nil
}

func RegisterIdentity(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	identityData := pb.RegisterIdentity{}
	err := DecodeMessage(message, &identityData)
	if err != nil {
		// TODO: decode error
		return protocol.ErrUnknownFunction, nil
	}
	if len(identityData.SignatureKey) != ed25519.PublicKeySize || len(identityData.EncryptedSignatureKey) != ed25519.PrivateKeySize ||
		len(identityData.ExchangeKey) != 32 || len(identityData.EncryptedExchangeKey) != 32 || len(identityData.Username) < 3 ||
		len(identityData.VerificationHash) != 16 || identityData.Username == "" {
		// TODO: argument error
		return protocol.ErrUnknownFunction, nil
	}
	identity := database.Identity{
		Address:               uuid.UUID{},
		Username:              identityData.Username,
		Name:                  identityData.Name,
		Bio:                   identityData.Bio,
		SignatureKey:          identityData.SignatureKey,
		EncryptedSignatureKey: identityData.EncryptedSignatureKey,
		ExchangeKey:           identityData.ExchangeKey,
		EncryptedExchangeKey:  identityData.EncryptedExchangeKey,
		VerificationHash:      identityData.VerificationHash,
	}
	err = identity.Insert()
	if err != nil {
		// TODO: internal server error
		return protocol.ErrNotImplemented, nil
	}
	err = identity.Link(session.User)
	if err != nil {
		// TODO: internal server error
		return protocol.ErrNotImplemented, nil
	}
	session.LinkedIdentities = append(session.LinkedIdentities, &identity)
	return protocol.NewReply(&pb.RegisterIdentityReply{Address:identity.Address[:]}), nil
}

func LinkIdentity(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	linkRequest := pb.LinkIdentity{}
	err := DecodeMessage(message, &linkRequest)
	if err != nil {
		return pb.Reply{}, err
	}
	return protocol.ErrNotImplemented, nil
}

func UnlinkIdentity(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func ListLinkedDevices(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}
