package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/event"
	"github.com/Rirush/safeMessages/smserver/server"
)

func init() {
	event.Register(pb.OperationCode_INFORMATION, Information)
	event.Register(pb.OperationCode_REGISTER_DEVICE, RegisterDevice)
	event.Register(pb.OperationCode_GENERATE_CHALLENGE, GenerateChallenge)
	event.Register(pb.OperationCode_AUTHORIZE, Authorize)
	event.Register(pb.OperationCode_REGISTER_IDENTITY, RegisterIdentity)
	event.Register(pb.OperationCode_LINK_IDENTITY, LinkIdentity)
	event.Register(pb.OperationCode_UNLINK_IDENTITY, UnlinkIdentity)
	event.Register(pb.OperationCode_LIST_LINKED_DEVICES, ListLinkedDevices)
	event.Register(pb.OperationCode_UPDATE_DEVICE, UpdateDevice)
	event.Register(pb.OperationCode_UPDATE_IDENTITY, UpdateIdentity)
	event.Register(pb.OperationCode_UPDATE_KEYS, UpdateKeys)
	event.Register(pb.OperationCode_QUERY_IDENTITIES, QueryIdentities)
	event.Register(pb.OperationCode_QUERY_CHATS, QueryChats)
	event.Register(pb.OperationCode_CREATE_CHAT, CreateChat)
	event.Register(pb.OperationCode_JOIN_CHAT, JoinChat)
	event.Register(pb.OperationCode_PENDING_CHATS, PendingChats)
	event.Register(pb.OperationCode_CHAT_MANAGEMENT, ChatManagement)
	event.Register(pb.OperationCode_SEND_MESSAGE, SendMessage)
	event.Register(pb.OperationCode_QUERY_MESSAGES, QueryMessages)
	event.Register(pb.OperationCode_EDIT_MESSAGE, EditMessage)
	event.Register(pb.OperationCode_LISTEN_FOR_EVENTS, ListenForEvents)
}

func Information(session *server.SessionData, message *pb.Message) (pb.Reply, error) {
	return protocol.NewReply(&pb.InformationReply{Version:"v0.1.0"}), nil
}
