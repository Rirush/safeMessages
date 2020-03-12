package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/database"
	"github.com/Rirush/safeMessages/smserver/event"
	"github.com/google/uuid"
)

func QueryIdentities(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	query := pb.QueryIdentities{}
	err := DecodeMessage(message, &query)
	if err != nil {
		return protocol.ErrUnmarshalFailure, nil
	}
	identity := database.Identity{}
	switch query.Query.(type) {
	case *pb.QueryIdentities_Username:
		username := query.Query.(*pb.QueryIdentities_Username)
		err = identity.FindByUsername(username.Username)
		if err != nil {
			return protocol.NewReply(&pb.QueryIdentitiesReply{Identities: []*pb.Identity{}}), nil
		}
		pidentity := &pb.Identity{
			Address:      identity.Address[:],
			Username:     identity.Username,
			Name:         identity.Name,
			Bio:          identity.Bio,
			SignatureKey: identity.SignatureKey,
			ExchangeKey:  identity.ExchangeKey,
		}
		return protocol.NewReply(&pb.QueryIdentitiesReply{Identities: []*pb.Identity{pidentity}}), nil
	case *pb.QueryIdentities_Address:
		addressBytes := query.Query.(*pb.QueryIdentities_Address)
		address, err := uuid.FromBytes(addressBytes.Address)
		if err != nil {
			return protocol.NewReply(&pb.QueryIdentitiesReply{Identities: []*pb.Identity{}}), nil
		}
		err = identity.FindByAddress(address)
		if err != nil {
			return protocol.NewReply(&pb.QueryIdentitiesReply{Identities: []*pb.Identity{}}), nil
		}
		pidentity := &pb.Identity{
			Address:               identity.Address[:],
			Username:              identity.Username,
			Name:                  identity.Name,
			Bio:                   identity.Bio,
			SignatureKey:          identity.SignatureKey,
			ExchangeKey:           identity.ExchangeKey,
		}
		return protocol.NewReply(&pb.QueryIdentitiesReply{Identities: []*pb.Identity{pidentity}}), nil
	default:
		return protocol.ErrNotImplemented, nil
	}
	//return protocol.ErrNotImplemented, nil
}

func QueryChats(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func QueryMessages(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}
