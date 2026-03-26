-- name: StoreKey :exec
INSERT INTO keystore (id, key_pem) VALUES (?, ?);

-- name: LoadKey :one
SELECT key_pem FROM keystore WHERE id = ?;

-- name: DeleteKey :execrows
DELETE FROM keystore WHERE id = ?;
