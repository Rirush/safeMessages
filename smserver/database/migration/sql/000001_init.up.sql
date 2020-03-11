CREATE TABLE devices (
    address UUID PRIMARY KEY,
    key BYTEA NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE identities (
    address UUID PRIMARY KEY,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    bio TEXT NOT NULL,
    signature_key BYTEA NOT NULL,
    encrypted_signature_key BYTEA NOT NULL,
    exchange_key BYTEA NOT NULL,
    encrypted_exchange_key BYTEA NOT NULL,
    verification_hash BYTEA NOT NULL
);

CREATE TABLE identity_link (
    link_id SERIAL8 PRIMARY KEY,
    identity UUID REFERENCES identities,
    device UUID REFERENCES devices
);

CREATE TABLE chats (
    address UUID PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    discovery_key TEXT
);

CREATE TABLE chat_members (
    link_id SERIAL8 PRIMARY KEY,
    member UUID REFERENCES identities,
    chat UUID REFERENCES chats
);

CREATE TABLE pending_members (
    pending_id SERIAL8 PRIMARY KEY,
    member UUID REFERENCES identities,
    invited_by UUID REFERENCES identities,
    chat UUID REFERENCES chats
);

CREATE TABLE messages (
    global_message_id SERIAL8 PRIMARY KEY,
    local_message_id BIGINT NOT NULL,
    sender UUID REFERENCES identities,
    signature BYTEA NOT NULL,
    message BYTEA NOT NULL,
    chat UUID REFERENCES chats,
    sent_at TIMESTAMPTZ
);