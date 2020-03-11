package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/event"
)

func UpdateDevice(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func UpdateIdentity(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func UpdateKeys(session *event.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}
