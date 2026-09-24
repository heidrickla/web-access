#!/usr/bin/env bash
# The page-script checks, then each guard broken in a copy to confirm its check goes red.
# A mutant counts as caught only when the check ran and reported a FAIL.
set -uo pipefail
cd "$(dirname "$0")/../.."
status=0
node tests/js/sessions.mjs || status=1

mutant() { # name sed-expr
  sed "$2" web/app.js > /tmp/app-mutant.js
  if cmp -s web/app.js /tmp/app-mutant.js; then
    echo "BROKEN   $1: the edit changed nothing"; status=1; return
  fi
  APP_JS=/tmp/app-mutant.js node tests/js/sessions.mjs > /tmp/mutant.out 2>&1
  if grep -q '^FAIL ' /tmp/mutant.out && grep -q '^passed=' /tmp/mutant.out; then
    echo "KILLED   $1"
  else
    echo "SURVIVED $1"; status=1
  fi
}

mutant "an upload reply goes to whichever session is current" "s/extOn(owner, 'submit_file_contents'/ext('submit_file_contents'/g"
mutant "a download request goes to whichever session is current" "s/extOn(owner, 'request_file_contents'/ext('request_file_contents'/"
mutant "a reply goes through an ended session" "s/  if (!owner || session !== owner) throw/  if (!owner) throw/"
mutant "an ended session's failed upload is reported" "s|    if (session !== owner) return;   // ended meanwhile: nobody to answer or tell||"

exit $status
