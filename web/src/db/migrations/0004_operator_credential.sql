-- operator_credential (D-01/D-02): the single operator-held Graph client
-- secret for the whole deployment, stored ONLY as AES-256-GCM ciphertext
-- (web/src/lib/crypto/encrypt.ts). The first-use claim is enforced in
-- web/src/lib/settings/operator-credential.ts, not here.
CREATE TABLE `operator_credential` (
	`id` text PRIMARY KEY NOT NULL,
	`secret_enc` text NOT NULL,
	`configured_by_account_id` text NOT NULL,
	`configured_at` integer NOT NULL
);
