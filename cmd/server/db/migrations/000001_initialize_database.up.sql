-- Create global address table

CREATE TABLE IF NOT EXISTS entities (
    address UUID PRIMARY KEY,
    type TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS entities_address_index ON entities (address);

-- Create device table

CREATE TABLE IF NOT EXISTS devices (
    address UUID PRIMARY KEY REFERENCES entities,
    name TEXT NOT NULL,
    description TEXT,
    public_signature_key BYTEA NOT NULL,
    public_exchange_key BYTEA NOT NULL,
    discover_key BYTEA,
    is_active BOOLEAN NOT NULL DEFAULT false,
    is_discoverable BOOLEAN NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX IF NOT EXISTS devices_address_index ON devices (address);

-- Create identity table

CREATE TABLE IF NOT EXISTS identities (
    address UUID PRIMARY KEY REFERENCES entities,
    username TEXT NOT NULL,
    name TEXT,
    description TEXT,
    public_signature_key BYTEA NOT NULL,
    private_signature_key BYTEA NOT NULL,
    public_exchange_key BYTEA NOT NULL,
    private_exchange_key BYTEA NOT NULL,
    verification_hash BYTEA NOT NULL,
    discover_key BYTEA,
    is_discoverable BOOLEAN NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_address_index ON identities (address);

CREATE TABLE IF NOT EXISTS discover_exception (
    exception_id SERIAL8 PRIMARY KEY,
    source UUID REFERENCES entities,
    destination UUID REFERENCES entities,
    allow BOOLEAN NOT NULL
);

-- Create conversation table

CREATE TABLE IF NOT EXISTS conversations (
    address UUID PRIMARY KEY REFERENCES entities,
    creator UUID REFERENCES entities,
    name TEXT,
    description TEXT,
    is_private BOOLEAN NOT NULL DEFAULT true,
    is_direct BOOLEAN NOT NULL,
    is_encrypted BOOLEAN NOT NULL,
    is_storable BOOLEAN NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS conversation_address_index ON conversations (address);

CREATE TABLE IF NOT EXISTS pending_conversation_members (
    request_id SERIAL8 PRIMARY KEY,
    conversation UUID REFERENCES conversations,
    member UUID REFERENCES entities,
    added_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create key change table

CREATE TABLE IF NOT EXISTS key_changes (
    change_id SERIAL8 PRIMARY KEY,
    identity UUID NOT NULL REFERENCES entities,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    old_public_signature_key BYTEA NOT NULL,
    old_public_exchange_key BYTEA NOT NULL
);

-- Create device link table

CREATE TABLE IF NOT EXISTS linked_devices (
    link_id SERIAL8 PRIMARY KEY,
    identity UUID REFERENCES identities,
    device UUID REFERENCES devices,
    linked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create conversation key table

CREATE TABLE IF NOT EXISTS conversation_keys (
    key_id SERIAL8 PRIMARY KEY,
    identity UUID REFERENCES identities,
    conversation UUID REFERENCES conversations,
    encrypted_key BYTEA NOT NULL
);

-- Create conversation token table

CREATE TABLE IF NOT EXISTS conversation_tokens (
    token_id SERIAL8 PRIMARY KEY,
    access_token BYTEA UNIQUE NOT NULL,
    issuer UUID REFERENCES entities,
    conversation UUID REFERENCES conversations,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX IF NOT EXISTS conversation_token_index ON conversation_tokens (access_token);

-- Create conversation member table

CREATE TABLE IF NOT EXISTS conversation_members (
    link_id SERIAL8 PRIMARY KEY,
    conversation UUID REFERENCES conversations,
    member UUID REFERENCES entities,
    used_token INT8 REFERENCES conversation_tokens
);

-- Create message table

CREATE TABLE IF NOT EXISTS messages (
    global_message_id SERIAL8 PRIMARY KEY,
    message_id INT8 NOT NULL,
    sender UUID REFERENCES entities,
    recipient UUID REFERENCES conversations,
    signature BYTEA,
    sent_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_encrypted BOOLEAN NOT NULL,
    contents BYTEA NOT NULL
);