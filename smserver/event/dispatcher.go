package event

import (
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func Dispatch(session *server.SessionData, message *pb.Message) (pb.Reply, error) {

	return pb.Reply{}, nil
}

var handlerMap map[pb.OperationCode]Handler

type Handler func(*server.SessionData, *pb.Message) (pb.Reply, error)

func Register(code pb.OperationCode, handler Handler) {
	handlerMap[code] = handler
}