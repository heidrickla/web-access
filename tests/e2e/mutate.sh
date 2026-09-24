#!/usr/bin/env bash
# Break each guard in a scratch copy and confirm the test that guards it goes red.
set -uo pipefail
export PATH=$HOME/.cargo/bin:$PATH
REPO=$(cd "$(dirname "$0")/../.." && pwd)
rm -rf ~/wa-mut && mkdir ~/wa-mut
cd "$REPO" && tar --exclude=./target -cf - . | tar -xf - -C ~/wa-mut
cd ~/wa-mut
export CARGO_TARGET_DIR=$HOME/wa-mut-target

mutate() { # name file sed-expr test-filter
  cp "$2" "$2.orig"
  sed -i "$3" "$2"
  if cmp -s "$2" "$2.orig"; then echo "BROKEN MUTATION $1: sed changed nothing"; mv "$2.orig" "$2"; return; fi
  if cargo test --offline -q "$4" >/tmp/mut.out 2>&1; then
    echo "SURVIVED $1 (test $4 still passes)"
  else
    echo "KILLED   $1"
  fi
  mv "$2.orig" "$2"
}

mutate "admin guard admits everyone" src/web.rs 's/if app.is_admin(&current.user) {/if true {/' a_non_admin_is_refused_on_every_admin_route
mutate "origin guard admits any origin" src/web.rs 's/if safe || same_origin(req.headers()) {/if true {/' a_cross_origin_post_is_refused
mutate "tickets are reusable" src/auth.rs 's/\.remove(token)?;/.get(token).map(|i| Issued { ticket: i.ticket, minted: i.minted })?;/' a_ticket_is_spent_by_its_first_use
mutate "credential AAD ignores the server" src/vault.rs 's/format!("credential\\0{sid}\\0{server_id}")/format!("credential\\0{sid}")/' a_credential_round_trips_and_is_bound_to_its_user_and_server
mutate "assignment predicate always true" src/store.rs 's/"SELECT 1 FROM assignments WHERE user_id = ?1 AND server_id = ?2",/"SELECT 1 FROM servers WHERE ?1 = ?1 AND id = ?2",/' an_unassigned_server_is_refused
mutate "session expiry ignored" src/store.rs 's/WHERE s.token_hash = ?1 AND s.expires > ?2"/WHERE s.token_hash = ?1 AND ?2 = ?2"/' a_session_lasts_a_full_day_and_no_longer
mutate "frozen host accepts saves" src/web.rs 's/        return Some("saving is paused while this proxy is being migrated");/        let _ = 0;/' a_frozen_proxy_refuses_saves
mutate "import skips the passphrase check" src/migrate.rs 's/let db = vault::decrypt_with_passphrase(passphrase, AAD_EXPORT, blob)?;/let db = vault::decrypt_with_passphrase(passphrase, AAD_EXPORT, blob).unwrap_or_default();/' a_tampered_export_changes_nothing
mutate "local accounts sign in when not allowed" src/web.rs 's/    if !app.cfg.allow_local_accounts {/    if false {/' a_local_account_cannot_sign_in_unless_allowed
mutate "any local password verifies" src/web.rs 's/    if !ok {/    if false \&\& !ok {/' a_local_account_signs_in_with_no_directory_at_all
mutate "the sweep checks local accounts against the directory" src/store.rs 's/WHERE u.local_hash IS NULL$/WHERE 1 = 1/' the_revocation_sweep_never_sees_local_accounts
mutate "clearing the SID keeps saved credentials" src/store.rs 's/tx.execute("DELETE FROM credentials WHERE user_id = ?1", \[id\])?;//' clearing_the_sid_drops_credentials_and_sessions
