#!/usr/bin/env bash
# Checks that support actions notify ONLY the member's gallery admins.
BASE=${BASE:-http://127.0.0.1:5000}
read -r -p "Super admin email: " SA_EMAIL
read -r -s -p "Super admin password: " SA_PASS; echo

PASS=0; FAIL=0
expect() { if [ "$2" = "$3" ]; then echo "PASS  $1 ($3)"; PASS=$((PASS+1)); else echo "FAIL  $1: expected $2, got $3"; FAIL=$((FAIL+1)); fi; }
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
field() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))"; }

SA=$(python3 -c "import json,sys; print(json.dumps({'email':sys.argv[1],'password':sys.argv[2]}))" "$SA_EMAIL" "$SA_PASS" \
  | curl -s -X POST "$BASE/platform-admin/login" -H 'Content-Type: application/json' -d @- | field access_token)
[ -z "$SA" ] && { echo "Super admin login failed"; exit 1; }

member_token() {  # gallery-slug role
  curl -s -X POST "$BASE/login" -H 'Content-Type: application/json' \
    -d '{"email":"'"$2"'@sandbox.test","password":"SandboxPass123!","org_slug":"'"$1"'"}' | field access_token
}
support_notes() {  # token -> how many "Platform support" notifications they can see
  curl -s "$BASE/notifications" -H "Authorization: Bearer $1" | grep -o "Platform support" | wc -l | tr -d ' '
}

A_ADMIN=$(member_token test-gallery-a admin);  A_CUR=$(member_token test-gallery-a curator)
A_MEM=$(member_token test-gallery-a member);   B_ADMIN=$(member_token test-gallery-b admin)

# Find test-gallery-a's id and its 'member@sandbox.test' id through the platform API.
ORG_A=$(curl -s "$BASE/platform-admin/galleries" -H "Authorization: Bearer $SA" \
  | python3 -c "import sys,json; print([g['id'] for g in json.load(sys.stdin)['galleries'] if g['slug']=='test-gallery-a'][0])")
MEM_A=$(curl -s "$BASE/platform-admin/galleries/$ORG_A/members" -H "Authorization: Bearer $SA" \
  | python3 -c "import sys,json; print([m['id'] for m in json.load(sys.stdin)['members'] if m['email']=='member@sandbox.test'][0])")
echo "gallery A id=$ORG_A, its sandbox member id=$MEM_A"

b1=$(support_notes "$A_ADMIN"); b2=$(support_notes "$B_ADMIN"); b3=$(support_notes "$A_CUR"); b4=$(support_notes "$A_MEM")

echo; echo "--- unlock"
expect "super admin unlocks the member" "200" "$(code -X POST "$BASE/platform-admin/galleries/$ORG_A/members/$MEM_A/unlock" -H "Authorization: Bearer $SA" -H 'Content-Type: application/json' -d '{}')"
expect "gallery A admin got 1 new notification"   "$((b1+1))" "$(support_notes "$A_ADMIN")"
expect "gallery B admin got none"                 "$b2"       "$(support_notes "$B_ADMIN")"
expect "gallery A curator got none"               "$b3"       "$(support_notes "$A_CUR")"
expect "the member themself got none"             "$b4"       "$(support_notes "$A_MEM")"

echo; echo "--- password reset (the email goes to a fake address, so SendGrid may refuse it)"
R=$(code -X POST "$BASE/platform-admin/galleries/$ORG_A/members/$MEM_A/reset-password" -H "Authorization: Bearer $SA")
after=$(support_notes "$A_ADMIN")
if [ "$R" = "200" ]; then expect "reset sent -> admin notified" "$((b1+2))" "$after"
else expect "reset NOT sent ($R) -> admin NOT notified" "$((b1+1))" "$after"; fi
expect "gallery B admin still none" "$b2" "$(support_notes "$B_ADMIN")"

echo; echo "$PASS passed, $FAIL failed."