CREATE TABLE user (
    id TEXT NOT NULL PRIMARY KEY,
    email_address TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE passkey (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    webauthn_credential_id BLOB NOT NULL UNIQUE,
    webauthn_authenticator_id BLOB NOT NULL,
    signature_algorithm TEXT NOT NULL,
    public_key BLOB NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE signup (
    id TEXT NOT NULL PRIMARY KEY,
    secret_hash BLOB NOT NULL,
    target_user_id TEXT NOT NULL,
    email_address TEXT NOT NULL,
    email_address_verification_code TEXT NOT NULL,
    email_address_verified INTEGER NOT NULL DEFAULT 0,
    passkey_webauthn_credential_id BLOB,
    passkey_signature_algorithm TEXT,
    passkey_public_key BLOB,
    passkey_webauthn_authenticator_id BLOB,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE passkey_signin (
    id TEXT NOT NULL PRIMARY KEY,
    challenge BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE email_code_signin (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    email_code_hash BLOB NOT NULL,
    email_code_salt BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE identity_verification (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    verifying_action TEXT NOT NULL,
    verifying_action_id TEXT NOT NULL,
    passkey_verification_challenge BLOB NOT NULL,
    email_code_hash BLOB,
    email_code_salt BLOB,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE email_address_update (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL, 
    identity_verified INTEGER NOT NULL DEFAULT 0,
    new_email_address TEXT,
    new_email_address_verification_code TEXT,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE passkey_registration (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL, 
    identity_verified INTEGER NOT NULL DEFAULT 0,
    passkey_webauthn_credential_id BLOB,
    passkey_signature_algorithm TEXT,
    passkey_public_key BLOB,
    passkey_webauthn_authenticator_id BLOB,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE passkey_deletion (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL, 
    passkey_id TEXT NOT NULL REFERENCES passkey(id) ON DELETE CASCADE,
    identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE account_deletion (
    id TEXT NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL, 
    identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;