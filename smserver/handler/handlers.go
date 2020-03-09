package handler

import (
	"github.com/Rirush/safeMessages/protocol"
	"github.com/Rirush/safeMessages/protocol/pb"
	"github.com/Rirush/safeMessages/smserver/event"
	"github.com/Rirush/safeMessages/smserver/server"
)

func init() {
	event.Register(pb.OperationCode_INFORMATION, Information, false)
	event.Register(pb.OperationCode_REGISTER_DEVICE, RegisterDevice, false)
	event.Register(pb.OperationCode_GENERATE_CHALLENGE, GenerateChallenge, false)
	event.Register(pb.OperationCode_AUTHORIZE, Authorize, false)
	event.Register(pb.OperationCode_REGISTER_IDENTITY, RegisterIdentity, true)
	event.Register(pb.OperationCode_LINK_IDENTITY, LinkIdentity, true)
	event.Register(pb.OperationCode_UNLINK_IDENTITY, UnlinkIdentity, true)
	event.Register(pb.OperationCode_LIST_LINKED_DEVICES, ListLinkedDevices, true)
	event.Register(pb.OperationCode_UPDATE_DEVICE, UpdateDevice, true)
	event.Register(pb.OperationCode_UPDATE_IDENTITY, UpdateIdentity, true)
	event.Register(pb.OperationCode_UPDATE_KEYS, UpdateKeys, true)
	event.Register(pb.OperationCode_QUERY_IDENTITIES, QueryIdentities, true)
	event.Register(pb.OperationCode_QUERY_CHATS, QueryChats, true)
	event.Register(pb.OperationCode_CREATE_CHAT, CreateChat, true)
	event.Register(pb.OperationCode_JOIN_CHAT, JoinChat, true)
	event.Register(pb.OperationCode_PENDING_CHATS, PendingChats, true)
	event.Register(pb.OperationCode_CHAT_MANAGEMENT, ChatManagement, true)
	event.Register(pb.OperationCode_SEND_MESSAGE, SendMessage, true)
	event.Register(pb.OperationCode_QUERY_MESSAGES, QueryMessages, true)
	event.Register(pb.OperationCode_EDIT_MESSAGE, EditMessage, true)
	event.Register(pb.OperationCode_LISTEN_FOR_EVENTS, ListenForEvents, true)
}

func Information(session *server.SessionData, message *pb.Packet) (pb.Reply, error) {
	return protocol.NewReply(&pb.InformationReply{Version:"v0.1.0"}), nil
}
