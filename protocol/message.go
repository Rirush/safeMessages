package protocol

import (
	"time"
)

//go:generate msgp

// MessageHeader represents message header included before body of each message
type MessageHeader struct {
	Type        string   `json:"type,omitempty" msg:"type"`
	Signature   []byte   `json:"sig,omitempty" msg:"sig"`
	Source      [16]byte `json:"src,omitempty" msg:"src"`
	Destination [16]byte `json:"dst,omitempty" msg:"dst"`
	Size        int      `json:"size,omitempty" msg:"size"`
}

// Message type constants
const (
	TypeError                   = "error"
	TypeForwardMessage          = "forward_raw"
	TypeForwardEncryptedMessage = "forward_raw_enc"

	TypeRegister            = "register"
	TypeSetEncoding         = "set_encoding"
	TypeIntroduceRequest    = "introduce_request"
	TypeIntroduce           = "introduce"
	TypeSetDiscoveryKey     = "set_discovery_key"
	TypeGetDiscoveryKey     = "get_discovery_key"
	TypeResolveAddress      = "resolve_address"
	TypeResolveDevice       = "resolve_device"
	TypeAllowResolution     = "allow_resolution"
	TypeDisallowResolution  = "disallow_resolution"
	TypeRequestConversation = "request_conversation"
	TypeReceiveMessages     = "receive_messages"
	TypeSendMessage         = "send_message"
)

type EmptyReply struct{}

// ForwardRawMessage asks server to send an unencrypted message. Body of ForwardMessage may contain any data.
// The server will not decode message body and will forward it in untouched form. Server will not raise an error
// even if destination client doesn't exist. Server will not store forwarded messages in database at all,
// if the server restarts and destination client hasn't received the message, it will be lost.
type ForwardRawMessage struct{}

// ForwardRawMessageReply indicates that the server has received the message
type ForwardRawMessageReply struct{}

// ForwardRawEncryptedMessage is the same as ForwardMessage, but the message body is expected by the recipient to be encrypted.
type ForwardRawEncryptedMessage struct{}

// ForwardRawEncryptedMessageReply indicates that the server has received the message
type ForwardRawEncryptedMessageReply struct{}

// Register message asks server to remember new device and assign it an address.
// This message must be signed with specified key.
// Client must keep both keys as they are required for future authorization and communication with other clients
type Register struct {
	PublicSignatureKey []byte `json:"sigkey,omitempty" msg:"sigkey"`
	PublicExchangeKey  []byte `json:"exchkey,omitempty" msg:"exchkey"`
	Name               string `json:"name,omitempty" msg:"name"`
	Description        string `json:"desc,omitempty" msg:"desc"`
}

// RegisterReply returns an assigned address to the client.
// Client must save this address as it is needed to authorize
type RegisterReply struct {
	Address [16]byte `json:"addr,omitempty" msg:"addr"`
}

// SetEncoding asks server to change message encoding.
// Default encoding is JSON. If client doesn't want to support JSON, this message must be sent first,
// as the server will try guessing encoding method of the first message.
// Other supported encoding is MessagePack, other formats may be added in the future
type SetEncoding struct {
	// Type represents encoding type. Can be either `json` or `msgpack`.
	Type string `json:"type,omitempty" msg:"type"`
}

// IntroduceRequest asks server to send challenge bytes that client needs to sign with his signature key.
// Address identifies which user tries to log in
type IntroduceRequest struct {
	Address [16]byte `json:"addr,omitempty" msg:"addr"`
}

// IntroduceRequestReply returns challenge bytes that client must sign in order to confirm his identity
type IntroduceRequestReply struct {
	Challenge []byte `json:"challenge,omitempty" msg:"challenge"`
}

// Introduce contains challenge bytes that the server has requested.
// This message must be signed and bytes must match the bytes received in IntroduceRequestReply
type Introduce struct {
	Challenge []byte `json:"challenge,omitempty" msg:"challenge"`
}

// IntroduceReply returns device name if the authorization was successful.
// If server failed to authenticate device, either ErrInvalidSignature or ErrChallengeMismatch will be raised
type IntroduceReply struct {
	Name string `json:"name,omitempty" msg:"name"`
}

// GetPrivacySettings requests privacy settings for current client
type GetPrivacySettings struct{}

// GetPrivacySettingsReply returns privacy settings for current client
type GetPrivacySettingsReply struct {
	Discoverable bool `json:"discoverable,omitempty" msg:"discoverable"`
}

// SetPrivacySettings asks server to change privacy settings for current client
type SetPrivacySettings struct {
	Discoverable bool `json:"discoverable,omitempty" msg:"discoverable"`
}

// SetPrivacySettingsReply indicates that server has successfully changed privacy settings
type SetPrivacySettingsReply struct{}

// SetDiscoverKey asks server to set discovery key.
// If DiscoveryKey is empty, it will be removed
type SetDiscoveryKey struct {
	DiscoveryKey []byte `json:"key,omitempty" msg:"key"`
}

// SetDiscoveryKeyReply indicates that key was set
type SetDiscoveryKeyReply struct{}

// GetDiscoveryKey asks server to return client's discovery key
type GetDiscoveryKey struct{}

// GetDiscoveryKeyReply returns client's discovery key
type GetDiscoveryKeyReply struct {
	// DiscoveryKey is empty if no key is set
	DiscoveryKey []byte `json:"key,omitempty" msg:"key"`
}

// ResolveAddress asks server to check entity table and see if the specified address exists and who it belongs to.
// If discover key matches key that was set on the server, an allow exception is automatically created
type ResolveAddress struct {
	Address [16]byte `json:"addr,omitempty" msg:"addr"`
	// DiscoverKey is a pre-shared key that allows resolution of hidden clients
	DiscoverKey []byte `json:"key,omitempty" msg:"key"`
}

// ResolveAddressReply returns who address belongs to. Type is either `device`, `identity`, or `conversation`.
// If address doesn't exist or discovery is disabled for the specific entity, ErrInvalidAddress will be raised
type ResolveAddressReply struct {
	Type string `json:"type,omitempty" msg:"type"`
}

// ResolveDevice asks server to return information about specific device, identified by address.
type ResolveDevice struct {
	Address [16]byte `json:"addr,omitempty" msg:"addr"`
}

// ResolveDeviceReply returns device information if device with specified address exists and is discoverable.
// If the device doesn't exist, address doesn't represent a device, or device discovery is disabled, ErrInvalid address will be raised
type ResolveDeviceReply struct {
	Name        string `json:"name,omitempty" msg:"name"`
	Description string `json:"desc,omitempty" msg:"desc"`
	// SignatureKey contains last signature key that the device has registered on the server
	SignatureKey []byte `json:"sigkey,omitempty" msg:"sigkey"`
	// ExchangeKey contains last exchange key that the device has registered on the server
	ExchangeKey []byte `json:"exchkey,omitempty" msg:"exchkey"`
}

// AllowResolution creates an exception in discoverability rule for specific client.
type AllowResolution struct {
	Address [16]byte `json:"addr,omitempty" msg:"addr"`
}

// AllowResolutionReply indicates that an exception was created.
// This method will not raise an error even if requested client doesn't exist
type AllowResolutionReply struct{}

// AllowResolution creates an exception in discoverability rule for specific client.
type DisallowResolution struct {
	Address [16]byte `json:"addr,omitempty" msg:"addr"`
}

// DisallowResolutionReply indicates that an exception was created.
// This method will not raise an error even if requested client doesn't exist
type DisallowResolutionReply struct{}

// RequestConversation asks server to start chat conversation between devices.
// Clients must not execute this method to exchange arbitrary data between each other (exchange keys, signature keys, and other data).
// Clients must execute this method to exchange text messages between each other.
// If one of the members has restricted discoverability or doesn't exist, it will be ignored.
// If all members have restricted discoverability or don't exist, ErrInvalidAddress will be raised
type RequestConversation struct {
	// Name represents conversation name. May be empty
	Name string `json:"name,omitempty" msg:"name"`
	// Description contains conversation description. May be empty
	Description string `json:"desc,omitempty" msg:"desc"`
	// Members contains an array of members. Client may not specify himself as a member, as it is assumed that client is a member of his conversation.
	// Members size must be 1 if chat is direct.
	Members [][16]byte `json:"members,omitempty" msg:"members"`
	// Private shows whether this conversation can have invite tokens or not.
	// Direct conversations cannot have invite tokens, this field will be set to false if direct is set to true
	Private bool `json:"private,omitempty" msg:"private"`
	// Direct shows whether this conversation is a group conversation or a direct chat
	Direct bool `json:"direct,omitempty" msg:"direct"`
	// Encrypted shows whether messages are E2E encrypted or not
	Encrypted bool `json:"encrypted,omitempty" msg:"encrypted"`
	// Storable shows whether the server can store messages or not.
	// If storable is set to false, server will store messages only if other parties are offline. When message is delivered to all members,
	// server will delete stored messages. This behaviour may be changed in future
	Storable bool `json:"storable,omitempty" msg:"storable"`
}

// RequestConversationReply returns conversation address and indicates, that members were notified about new conversation
type RequestConversationReply struct {
	Address [16]byte `json:"addr,omitempty" msg:"addr"`
	// Members contains all invited members
	Members [][16]byte `json:"members,omitempty" msg:"members"`
}

// ReceiveMessages tells the server that no more commands will be sent through this connection.
// Server will start sending all incoming messages on this connection
type ReceiveMessages struct {
	// Filter allows clients to limit message sources
	Filter [][16]byte `json:"filter,omitempty" msg:"filter"`
}

// SendMessage tells server to send a message into specific conversation, specified by Destination field in the header
type SendMessage struct {
	Text string `json:"text,omitempty" msg:"text"`
}

type SendMessageReply struct {
	MessageID uint64    `json:"id,omitempty" msg:"id"`
	SentAt    time.Time `json:"sent_at,omitempty" msg:"sent_at"`
}

// All existing error codes
const (
	ErrInvalidSignature uint32 = iota
	ErrChallengeMismatch
	ErrInvalidAddress
	ErrInvalidDestination
	ErrAuthorizationRequired
	ErrDeserializationFailure
	ErrInternalServerError
	ErrUnknownType
	ErrInvalidArgument
	ErrNoPendingChallenge
)

// All existing error descriptions
const (
	ErrInvalidSignatureDesc       = "Signature verification failure"
	ErrChallengeMismatchDesc      = "Challenge bytes are different"
	ErrInvalidAddressDesc         = "Invalid address"
	ErrInvalidDestinationDesc     = "Invalid destination address"
	ErrAuthorizationRequiredDesc  = "Authorization required"
	ErrDeserializationFailureDesc = "Message deserialization failed"
	ErrInternalServerErrorDesc    = "Internal server error has occurred"
	ErrUnknownTypeDesc            = "Unknown message type"
	ErrInvalidArgumentDesc        = "Invalid argument"
	ErrNoPendingChallengeDesc     = "No challenge was created for current session"
)

// Error returns error that was raised by the server
type Error struct {
	Code        uint32      `json:"code" msg:"code"`
	Description string      `json:"desc" msg:"desc"`
	Details     interface{} `json:"details,omitempty" msg:"details"`
}

func NewError(code uint32, desc string) (MessageHeader, Error) {
	err := Error{
		Code:        code,
		Description: desc,
	}
	return MessageHeader{
		Type:        TypeError,
		Signature:   nil,
		Source:      [16]byte{},
		Destination: [16]byte{},
		Size:        err.Msgsize(),
	}, err
}
