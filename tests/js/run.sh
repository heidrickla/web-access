#!/usr/bin/env bash
# The page-script checks, then each guard broken in a copy to confirm its check goes red.
# A mutant counts as caught only when the check ran and reported a FAIL.
set -uo pipefail
cd "$(dirname "$0")/../.."
status=0
node tests/js/sessions.mjs || status=1
node tests/js/instance.mjs || status=1
node tests/js/settings.mjs || status=1

mutant() { # name page sed-expr check
  sed "$3" "$2" > /tmp/page-mutant.js
  if cmp -s "$2" /tmp/page-mutant.js; then
    echo "BROKEN   $1: the edit changed nothing"; status=1; return
  fi
  local var=APP_JS
  [ "$2" = web/admin.js ] && var=ADMIN_JS
  env "$var=/tmp/page-mutant.js" node "$4" > /tmp/mutant.out 2>&1
  if grep -q '^FAIL ' /tmp/mutant.out && grep -q '^passed=' /tmp/mutant.out; then
    echo "KILLED   $1"
  else
    echo "SURVIVED $1"; status=1
  fi
}

S=tests/js/sessions.mjs
I=tests/js/instance.mjs
T=tests/js/settings.mjs
mutant "an upload reply goes to whichever session is current" web/app.js "s/extOn(owner, 'submit_file_contents'/ext('submit_file_contents'/g" $S
mutant "a download request goes to whichever session is current" web/app.js "s/extOn(owner, 'request_file_contents'/ext('request_file_contents'/" $S
mutant "a reply goes through an ended session" web/app.js "s/  if (!owner || session !== owner) throw/  if (!owner) throw/" $S
mutant "an ended session's failed upload is reported" web/app.js "s|    if (session !== owner) return;   // ended meanwhile: nobody to answer or tell||" $S
mutant "the user page sends no instance" web/app.js "s/  if (dataInstance) headers\['X-Data-Instance'\] = dataInstance;//" $I
mutant "the user page goes on after the data was replaced" web/app.js "s/^    location.reload();$/    void 0;/" $I
mutant "the admin page sends no instance" web/admin.js "s/  if (dataInstance) init.headers\['X-Data-Instance'\] = dataInstance;//" $I
mutant "the admin page goes on after the data was replaced" web/admin.js "s/^      location.reload();$/      void 0;/" $I
mutant "an upload over the limit is sent anyway" web/app.js "s/  const over = tooLarge(Array.from(files), limit);/  const over = [];/" $T
mutant "a download over the limit is fetched anyway" web/app.js "s/    if (tooLarge(\[{ size: total }\], limit).length) {/    if (false) {/" $T
mutant "a file exactly at the limit is refused" web/app.js "s/files.filter(f => Number(f.size) > limit)/files.filter(f => Number(f.size) >= limit)/" $T
mutant "the renewal point ignores the Settings tab" web/app.js "s/  return me \&\& Number.isFinite(me.renew_below_secs) ? me.renew_below_secs : 18 \* 60 \* 60;/  return 18 * 60 * 60;/" $T
mutant "the server's default domain is not filled in" web/app.js "s/  return prefill.domain || server.domain || '';/  return prefill.domain || '';/" $T

exit $status
