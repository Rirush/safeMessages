package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func QueryIdentities(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func QueryChats(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func QueryMessages(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}
