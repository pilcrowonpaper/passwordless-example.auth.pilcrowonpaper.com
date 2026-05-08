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
    cose_public_key BLOB NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX passkey_user_id_index ON passkey(user_id);

CREATE TABLE auth_session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX auth_session_user_id_index ON auth_session(user_id);

CREATE TABLE signup_session (
    id TEXT NOT NULL PRIMARY KEY,
    secret_hash BLOB NOT NULL,
    target_user_id TEXT NOT NULL,
    email_address TEXT NOT NULL,
    email_address_verification_code TEXT NOT NULL,
    email_address_verified INTEGER NOT NULL DEFAULT 0,
    passkey_webauthn_credential_id BLOB,
    passkey_cose_public_key BLOB,
    passkey_webauthn_authenticator_id BLOB,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE passkey_signin_attempt (
    id TEXT NOT NULL PRIMARY KEY,
    challenge BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE email_code_signin_session (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    email_code TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX email_code_signin_session_user_id_index ON email_code_signin_session(user_id);

CREATE TABLE identity_verification_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    verifying_action TEXT NOT NULL,
    verifying_action_id TEXT NOT NULL,
    passkey_verification_challenge BLOB NOT NULL,
    email_code TEXT,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX identity_verification_session_auth_session_id ON identity_verification_session(auth_session_id);
CREATE INDEX identity_verification_session_verifying_action_id_index ON identity_verification_session(verifying_action_id);

CREATE TABLE email_address_update_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    identity_verified INTEGER NOT NULL DEFAULT 0,
    new_email_address TEXT,
    new_email_address_verification_code TEXT,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX email_address_update_session_auth_session_id_index ON email_address_update_session(auth_session_id);

CREATE TABLE passkey_registration_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    identity_verified INTEGER NOT NULL DEFAULT 0,
    passkey_webauthn_credential_id BLOB,
    passkey_cose_public_key BLOB,
    passkey_webauthn_authenticator_id BLOB,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX passkey_registration_session_auth_session_id_index ON passkey_registration_session(auth_session_id);

CREATE TABLE passkey_deletion_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    passkey_id TEXT NOT NULL REFERENCES passkey(id) ON DELETE CASCADE,
    identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX passkey_deletion_session_auth_session_id_index ON passkey_deletion_session(auth_session_id);

CREATE TABLE account_deletion_session (
    id TEXT NOT NULL PRIMARY KEY,
    auth_session_id TEXT NOT NULL REFERENCES auth_session(id) ON DELETE CASCADE,
    secret_hash BLOB NOT NULL,
    identity_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX account_deletion_session_auth_session_id_index ON account_deletion_session(auth_session_id);
