package handler

import (
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func RegisterDevice(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func GenerateChallenge(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func Authorize(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func RegisterIdentity(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func LinkIdentity(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func UnlinkIdentity(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}

func ListLinkedDevices(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

}
