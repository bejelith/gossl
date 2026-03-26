-- name: CreateCA :one
INSERT INTO ca (parent_id, common_name, serial, key_algo, cert_pem, not_before, not_after, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetCA :one
SELECT * FROM ca WHERE id = ?;

-- name: GetCABySerial :one
SELECT * FROM ca WHERE serial = ?;

-- name: GetCAByCN :one
SELECT * FROM ca WHERE common_name = ?;

-- name: GetRootCA :one
SELECT * FROM ca WHERE parent_id IS NULL;

-- name: ListCAs :many
SELECT * FROM ca ORDER BY created_at DESC;

-- name: ListCAsByParent :many
SELECT * FROM ca WHERE parent_id = ? ORDER BY created_at DESC;

-- name: CreateCert :one
INSERT INTO cert (ca_id, common_name, serial, key_algo, cert_pem, not_before, not_after, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetCert :one
SELECT * FROM cert WHERE id = ?;

-- name: GetCertBySerial :one
SELECT * FROM cert WHERE serial = ?;

-- name: GetCertByCN :one
SELECT * FROM cert WHERE common_name = ?;

-- name: ListCerts :many
SELECT * FROM cert ORDER BY created_at DESC;

-- name: ListCertsByCA :many
SELECT * FROM cert WHERE ca_id = ? ORDER BY created_at DESC;

-- name: RevokeCert :execrows
UPDATE cert SET revoked_at = ? WHERE serial = ?;
