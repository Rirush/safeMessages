package main

import (
	"github.com/google/uuid"
	"time"
)

type Entities struct {
	Address uuid.UUID `dbq:"address"`
	Type    string    `dbq:"type"`
}

type Devices struct {
	Address            uuid.UUID `dbq:"address"`
	Name               string    `dbq:"name"`
	Description        string    `dbq:"description"`
	PublicSignatureKey []byte    `dbq:"public_signature_key"`
	PublicExchangeKey  []byte    `dbq:"public_exchange_key"`
	IsActive           bool      `dbq:"is_active"`
	IsDiscoverable     bool      `dbq:"is_discoverable"`
}

type Identity struct {
	Address             uuid.UUID `dbq:"address"`
	Username            string    `dbq:"username"`
	Name                string    `dbq:"name"`
	Description         string    `dbq:"description"`
	PublicSignatureKey  []byte    `dbq:"public_signature_key"`
	PrivateSignatureKey []byte    `dbq:"private_signature_key"`
	PublicExchangeKey   []byte    `dbq:"public_exchange_key"`
	PrivateExchangeKey  []byte    `dbq:"private_exchange_key"`
	VerificationHash    []byte    `dbq:"verification_hash"`
	IsDiscoverable      bool      `dbq:"is_discoverable"`
}

type Conversation struct {
	Address     uuid.UUID `dbq:"address"`
	Name        string    `dbq:"name"`
	IsPrivate   bool      `dbq:"is_private"`
	IsDirect    bool      `dbq:"is_direct"`
	IsEncrypted bool      `dbq:"is_encrypted"`
	IsStorable  bool      `dbq:"is_storable"`
}

type KeyChange struct {
	ChangeID              uint64    `dbq:"change_id"`
	Identity              uuid.UUID `dbq:"identity"`
	ChangedAt             time.Time `dbq:"changed_at"`
	OldPublicSignatureKey []byte    `dbq:"old_public_signature_key"`
	OldPublicExchangeKey  []byte    `dbq:"old_public_exchange_key"`
}

type LinkedDevice struct {
	LinkID   uint64    `dbq:"link_id"`
	Identity uuid.UUID `dbq:"identity"`
	Device   uuid.UUID `dbq:"device"`
	LinkedAt time.Time `dbq:"linked_at"`
}

type ConversationKey struct {
	KeyID        uint64    `dbq:"key_id"`
	Identity     uuid.UUID `dbq:"identity"`
	Conversation uuid.UUID `dbq:"conversation"`
	EncryptedKey []byte    `dbq:"encrypted_key"`
}

type ConversationToken struct {
	TokenID      uint64    `dbq:"token_id"`
	AccessToken  []byte    `dbq:"access_token"`
	Issuer       uuid.UUID `dbq:"issuer"`
	Conversation uuid.UUID `dbq:"conversation"`
	IssuedAt     time.Time `dbq:"issued_at"`
	IsActive     bool      `dbq:"is_active"`
}

type ConversationMember struct {
	LinkID       uint64    `dbq:"link_id"`
	Conversation uuid.UUID `dbq:"conversation"`
	Member       uuid.UUID `dbq:"member"`
	UsedToken    uint64    `dbq:"used_token"`
}

type Message struct {
	GlobalMessageID uint64    `dbq:"global_message_id"`
	MessageID       uint64    `dbq:"message_id"`
	Sender          uuid.UUID `dbq:"sender"`
	Recipient       uuid.UUID `dbq:"recipient"`
	Signature       []byte    `dbq:"signature"`
	SentAt          time.Time `dbq:"sent_at"`
	IsEncrypted     bool      `dbq:"is_encrypted"`
	Contents        []byte    `dbq:"contents"`
}
