package handler

import (
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func CreateChat(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func JoinChat(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func PendingChats(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func ChatManagement(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func SendMessage(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func EditMessage(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func ListenForEvents(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}
