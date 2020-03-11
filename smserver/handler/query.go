package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/database"
	"github.com/Rirush/safeMessages/smserver/event"
)

func QueryIdentities(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	query := pb.QueryIdentities{}
	err := DecodeMessage(message, &query)
	if err != nil {
		// TODO: decode error
		return protocol.ErrUnknownFunction, nil
	}
	identity := database.Identity{}
	switch query.Query.(type) {
	case *pb.QueryIdentities_Username:
		username := query.Query.(*pb.QueryIdentities_Username)
		err = identity.FindByUsername(username.Username)
		if err != nil {
			// TODO: no such username
			return protocol.NewReply(&pb.QueryIdentitiesReply{Identities:nil}), nil
		}
		pidentity := &pb.Identity{
			Address:      identity.Address[:],
			Username:     identity.Username,
			Bio:          identity.Bio,
			SignatureKey: identity.SignatureKey,
			ExchangeKey:  identity.ExchangeKey,
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
