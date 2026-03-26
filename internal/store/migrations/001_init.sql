CREATE TABLE IF NOT EXISTS ca (
    id          INTEGER PRIMARY KEY,
    parent_id   INTEGER REFERENCES ca(id),
    common_name TEXT NOT NULL,
    serial      TEXT NOT NULL UNIQUE,
    key_algo    TEXT NOT NULL,
    cert_pem    TEXT NOT NULL,
    not_before  DATETIME NOT NULL,
    not_after   DATETIME NOT NULL,
    created_at  DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS cert (
    id              INTEGER PRIMARY KEY,
    ca_id           INTEGER NOT NULL REFERENCES ca(id),
    common_name     TEXT NOT NULL,
    serial          TEXT NOT NULL UNIQUE,
    key_algo        TEXT NOT NULL,
    cert_pem        TEXT NOT NULL,
    not_before      DATETIME NOT NULL,
    not_after       DATETIME NOT NULL,
    revoked_at      DATETIME,
    created_at      DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS keystore (
    id      TEXT PRIMARY KEY,
    key_pem BLOB NOT NULL
);
