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

mutate "admin guard admits everyone" src/web.rs 's/    if app.is_admin(&user) {/    if true {/' a_non_admin_is_refused_on_every_admin_route
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
mutate "freezing export without the exclusive gate" src/admin.rs '/= if freeze {$/,/snapshot_of/ s/let _exclusive = app.gate.write().await;//' a_freezing_export_waits_for_edits_in_flight_and_a_wrong_passphrase_freezes_nothing
mutate "the gate is held while the body arrives" src/web.rs 's/    let (parts, body) = req.into_parts();/    let _early = app.gate.read().await; let (parts, body) = req.into_parts();/' a_slow_body_does_not_hold_the_gate
mutate "sign-out keeps connections" src/web.rs 's/    app.live.end_session(&current.token_hash);//' signing_out_ends_its_connections
mutate "an import runs inside its request" src/admin.rs 's/    tokio::spawn(op(gone)).await.map_err(ApiError::internal)?/    op(gone).await/' an_import_that_has_the_gate_finishes_after_its_request_ends
mutate "an export runs inside its request" src/admin.rs 's/    tokio::spawn(op(gone)).await.map_err(ApiError::internal)?/    op(gone).await/' an_export_nobody_receives_leaves_no_freeze
mutate "an abandoned import still runs" src/admin.rs '/pub async fn import_exclusive/,/^}/ s/still_wanted(&gone)?;//' an_import_abandoned_before_it_has_the_gate_does_not_run
mutate "the import trusts the session it started with" src/admin.rs '/pub async fn import_exclusive/,/^}/ s/let admin = revalidate_admin(&app, &token)?;/let admin = app.store.user_by_name("boss")?.unwrap();/' a_migration_request_is_authorized_again_once_it_has_the_gate
mutate "the export trusts the session it started with" src/admin.rs '/^async fn export_task/,/^}/ s/let admin = revalidate_admin(&app, &token)?;/let admin = app.store.user_by_name("boss")?.unwrap();/' a_migration_request_is_authorized_again_once_it_has_the_gate
mutate "the upload trusts the session it started with" src/admin.rs '/^async fn upload_import/,/^}/ s/let admin = revalidate_admin(&app, &token)?;/let admin = app.store.user_by_name("boss")?.unwrap();/' a_migration_request_is_authorized_again_once_it_has_the_gate
mutate "exports run concurrently" src/admin.rs 's/    let one = Arc::clone(&app.export_lock).lock_owned().await;/    let one = Arc::new(tokio::sync::Mutex::new(())).lock_owned().await;/' exports_run_one_at_a_time
mutate "the next export starts before a freeze is settled" src/admin.rs 's/        if let Some((app, generation, lock)) = self.0.take() {/        if let Some((app, generation, early)) = self.0.take() { drop(early); let lock = ();/' a_delivery_lifts_its_freeze_unless_handed_over
mutate "a failed export lifts a freeze it did not set" src/admin.rs 's/        let froze = !app.frozen();/        let froze = true;/' an_export_undoes_only_a_freeze_it_set
mutate "an undelivered export stays frozen" src/admin.rs 's/                        unfreeze_if_current(&app, generation).await;//' an_export_nobody_receives_leaves_no_freeze
mutate "an export nobody received is recorded" src/admin.rs 's/^    still_wanted(&gone)?;$//' an_export_cancelled_while_waiting_to_record_itself_lifts_its_freeze
mutate "a handed-over archive loses its freeze" src/admin.rs 's/            undo.disarm();//' a_delivery_lifts_its_freeze_unless_handed_over
mutate "an export records itself in a replaced database" src/admin.rs '/^async fn export_task/,/^}/ s/    if app.generation() == generation {/    if true {/' an_export_records_nothing_in_a_database_replaced_since_its_snapshot
mutate "a session opening is recorded in a replaced database" src/proxy.rs '/async fn record_open/,/^    }/ s/        if self.app.live.generation_of(self.live_id) != Some(self.app.generation()) {/        if false {/' a_session_opened_across_an_import_records_nothing_in_the_new_database
mutate "the export trusts a passphrase checked on the live database" src/migrate.rs 's/    Vault::verify_recovery(&Store::open(&tmp.0)?, passphrase)?;//' an_export_is_checked_against_the_wrap_in_its_own_snapshot
mutate "an import leaves the generation alone" src/migrate.rs 's/    app.bump_generation();//' an_import_waits_for_requests_in_flight_and_ends_every_connection
mutate "admission ignores the generation" src/proxy.rs '/pub async fn admit/,/^    }/ s/        if self.app.live.generation_of(self.live_id) != Some(self.app.generation()) {/        if false {/' admission_refuses_a_connection_from_before_an_import
mutate "a session end is recorded in a replaced database" src/proxy.rs 's/    if e.generation != app.generation() {/    if false {/' a_session_ended_by_an_import_writes_nothing_into_the_new_database
mutate "sign-in hashes under the gate" src/web.rs 's/    ("POST", "\/api\/login"),//' a_local_sign_in_hashes_within_the_bound_and_outside_the_gate
mutate "sign-in hashes without a permit" src/web.rs 's/    let permit = Arc::clone(&app.hash_permits)/    let permit = Arc::new(tokio::sync::Semaphore::new(1))/' a_local_sign_in_hashes_within_the_bound_and_outside_the_gate
mutate "sign-in records into a replaced database" src/web.rs 's/    if app.generation() != generation {/    if false {/' a_sign_in_that_straddles_an_import_is_not_recorded
mutate "local sign-in is never throttled" src/web.rs 's/    if app.throttle.blocked(username) {/    if false {/' repeated_local_failures_are_refused_without_hashing
mutate "a WebSocket upgrade gives up its connection's place" src/server.rs 's/        req.extensions_mut().insert(permit.clone());//' a_websocket_setting_up_keeps_its_place_under_the_limit
mutate "a connection entry outlives its task" src/live.rs 's/        self.app.live.remove(self.id);//' a_panicking_session_task_leaves_no_entry
mutate "a directory sign-in lands on a local account" src/web.rs 's/    if user.local {/    if false {/' a_directory_sign_in_never_lands_on_a_local_account
mutate "a local failure is counted only if its request waits" src/web.rs 's/            counter.throttle.fail(&name);//; s/        return Ok(Checked::Refused("local password did not match"));/        app.throttle.fail(username); return Ok(Checked::Refused("local password did not match"));/' an_abandoned_local_sign_in_still_counts_as_a_failure
mutate "a freeze is not marked pending" src/admin.rs 's/            app.store.set_flag(META_FREEZE_PENDING, true)?;//' a_freeze_is_pending_until_its_archive_is_handed_over
mutate "a handed-over freeze stays pending" src/admin.rs 's/^                app.store.set_flag(META_FREEZE_PENDING, false)?;$//' a_freeze_is_pending_until_its_archive_is_handed_over
mutate "the freeze stops being pending before the handover" src/admin.rs 's/^    Ok(delivery)$/    if froze { app.store.set_flag(META_FREEZE_PENDING, false)?; } Ok(delivery)/' a_freeze_is_pending_until_its_archive_is_handed_over
mutate "start keeps a stranded freeze" src/app.rs 's/        app.lift_stranded_freeze()?;//' a_stranded_freeze_is_lifted_when_the_service_starts_and_only_then
mutate "a command-line tool lifts a freeze in progress" src/app.rs 's/        app.seed_from_config()?;/        app.seed_from_config()?; app.lift_stranded_freeze()?;/' a_stranded_freeze_is_lifted_when_the_service_starts_and_only_then
mutate "the service start keeps a stranded freeze" src/server.rs 's/    let app = Arc::new(App::for_serving(cfg)?);/    let app = Arc::new(App::new(cfg)?);/' the_service_start_lifts_a_stranded_freeze
mutate "a second serving process starts" src/server.rs 's/    match file.try_lock() {/    match Ok::<(), std::fs::TryLockError>(()) {/' a_second_serving_process_changes_nothing
mutate "the serving lock goes before the runtime's blocking work" src/server.rs 's/^    drop(runtime);$/    drop(lock); let lock = ();/' the_serving_lock_outlives_blocking_work_left_at_shutdown
mutate "a sign-in session goes to a row that reused its id" src/store.rs 's/             SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2 AND incarnation = ?5)",/             SELECT ?1, ?2, ?3, ?4 WHERE ?5 = ?5",/' a_sign_in_never_lands_on_a_row_that_reused_its_id
mutate "a sign-in is recorded on a row that reused its id" src/store.rs 's/             WHERE id = ?1 AND incarnation = ?5",/             WHERE id = ?1 AND ?5 = ?5",/' a_sign_in_never_lands_on_a_row_that_reused_its_id
mutate "sign-in ignores a refused session" src/web.rs 's/    if !app.store.session_create(/    if false \&\& !app.store.session_create(/' a_sign_in_gets_no_session_on_a_row_that_reused_its_id
mutate "a session end lands on a row that reused its id" src/store.rs 's/              WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1 AND incarnation = ?2)/              WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1 AND ?2 = ?2)/' a_late_session_end_never_lands_on_a_row_that_reused_its_id
mutate "a session end lands on a server that reused its id" src/store.rs 's/                AND EXISTS (SELECT 1 FROM servers WHERE id = ?3 AND incarnation = ?4)/                AND EXISTS (SELECT 1 FROM servers WHERE id = ?3 AND ?4 = ?4)/' a_late_session_end_never_lands_on_a_row_that_reused_its_id
mutate "a new row keeps no incarnation" src/store.rs 's/^BEGIN UPDATE users SET incarnation = random() WHERE id = NEW.id; END;$/BEGIN SELECT 1; END;/' a_late_session_end_never_lands_on_a_row_that_reused_its_id

if [ "$bad" -eq 0 ]; then echo "all mutations caught"; else echo "$bad mutation(s) not caught"; exit 1; fi
