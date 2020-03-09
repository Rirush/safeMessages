package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func CreateChat(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func JoinChat(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func PendingChats(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func ChatManagement(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func SendMessage(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func EditMessage(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}

func ListenForEvents(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.ErrNotImplemented, nil
}
