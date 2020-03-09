package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func RegisterDevice(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func GenerateChallenge(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func Authorize(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func RegisterIdentity(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func LinkIdentity(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func UnlinkIdentity(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func ListLinkedDevices(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}
