#!/usr/bin/env bash
# Break each guard in a scratch copy and confirm the test that guards it goes red.
set -uo pipefail
export PATH=$HOME/.cargo/bin:$PATH
REPO=$(cd "$(dirname "$0")/../.." && pwd)
rm -rf ~/wa-mut && mkdir ~/wa-mut
cd "$REPO" && tar --exclude=./target -cf - . | tar -xf - -C ~/wa-mut
cd ~/wa-mut
export CARGO_TARGET_DIR=$HOME/wa-mut-target

bad=0

# A mutation counts as caught only when the mutant COMPILES and its named test then FAILS. A mutant
# that does not compile, or a test filter that matches nothing, proves nothing and fails the run.
mutate() { # name file sed-expr test-filter
  # ONLY=<text> runs just the mutations whose name contains it.
  if [ -n "${ONLY:-}" ] && [[ "$1" != *"$ONLY"* ]]; then return; fi
  cp "$2" "$2.orig"
  sed -i "$3" "$2"
  if cmp -s "$2" "$2.orig"; then
    echo "BROKEN   $1: the edit changed nothing"; bad=$((bad+1)); mv "$2.orig" "$2"; return
  fi
  if ! cargo test --offline -q --no-run >/tmp/mut.out 2>&1; then
    echo "BROKEN   $1: the mutant does not compile"; bad=$((bad+1)); mv "$2.orig" "$2"; return
  fi
  cargo test --offline -q "$4" -- --list >/tmp/mut.list 2>&1
  if ! grep -q "$4: test" /tmp/mut.list; then
    echo "BROKEN   $1: no test named $4"; bad=$((bad+1)); mv "$2.orig" "$2"; return
  fi
  if cargo test --offline -q "$4" >/tmp/mut.out 2>&1; then
    echo "SURVIVED $1 (test $4 still passes)"; bad=$((bad+1))
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
mutate "admission ignores an ended sign-in" src/proxy.rs 's/            Ok(_) => return Err(Refusal::SignInEnded),/            Ok(_) => {}/' admission_refuses_once_the_sign_in_has_ended
mutate "a pending connection ignores its end signal" src/proxy.rs 's/            _ = ended => {/            _ = std::future::pending::<()>() => {/' a_connection_still_setting_up_is_ended_by_revocation
mutate "connections outlive their sign-in" src/server.rs 's/            Ok(None) => true,/            Ok(None) => false,/' a_connection_whose_sign_in_ended_is_closed
mutate "the directory check skips live users" src/server.rs 's/    for id in app.live.user_ids() {/    for id in std::collections::HashSet::<i64>::new() {/' users_with_a_connection_are_checked_even_without_a_sign_in_row
mutate "no TLS handshake deadline" src/server.rs 's/tokio::time::timeout(limits.tls_handshake, acceptor.accept(stream))/tokio::time::timeout(Duration::from_secs(3600), acceptor.accept(stream))/' a_silent_tls_client_is_dropped_at_the_handshake_deadline
mutate "no connection limit" src/server.rs 's/Semaphore::new(limits.max_connections)/Semaphore::new(1 << 20)/' connections_over_the_limit_are_closed_on_accept
mutate "import without the exclusive gate" src/admin.rs '/pub async fn import_exclusive/,/^}/ s/let _exclusive = app.gate.write().await;//' an_import_waits_for_requests_in_flight_and_ends_every_connection
mutate "import keeps connections" src/migrate.rs 's/    app.live.end_all();//' an_import_waits_for_requests_in_flight_and_ends_every_connection
mutate "freezing export without the exclusive gate" src/admin.rs '/if req.freeze {$/,/take_snapshot/ s/let _exclusive = app.gate.write().await;//' a_freezing_export_waits_for_edits_in_flight_and_a_wrong_passphrase_freezes_nothing
mutate "the gate is held while the body arrives" src/web.rs 's/    let (parts, body) = req.into_parts();/    let _early = app.gate.read().await; let (parts, body) = req.into_parts();/' a_slow_body_does_not_hold_the_gate
mutate "sign-out keeps connections" src/web.rs 's/    app.live.end_session(&current.token_hash);//' signing_out_ends_its_connections

if [ "$bad" -eq 0 ]; then echo "all mutations caught"; else echo "$bad mutation(s) not caught"; exit 1; fi
