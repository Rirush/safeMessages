package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func UpdateDevice(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func UpdateIdentity(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func UpdateKeys(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}
