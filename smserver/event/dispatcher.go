package event

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/server"
)

func HandlePacket(session *server.SessionData, packet *pb.Packet) (pb.Reply, error) {
	f, ok := handlerMap[packet.Code]
	if !ok {
		return protocol.ErrUnknownFunction, nil
	}
	if !CheckPermissions(packet.Code, session.Authenticated) {
		return protocol.ErrUnauthorized, nil
	}
	return f(session, packet)
}

var handlerMap map[pb.OperationCode]Handler
var authorizationMap map[pb.OperationCode]bool

type Handler func(*server.SessionData, *pb.Packet) (pb.Reply, error)

func Register(code pb.OperationCode, handler Handler, authorized bool) {
	handlerMap[code] = handler
	authorizationMap[code] = authorized
}

func CheckPermissions(code pb.OperationCode, authenticated bool) bool {
	return authenticated || !authorizationMap[code]
}