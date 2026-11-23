#!/usr/bin/env bash
# Platform-admin + upload checks against a RUNNING server (flask run).
# Run:  bash platform_upload_test.sh      (override port with BASE=http://127.0.0.1:5001)
BASE=${BASE:-http://127.0.0.1:5000}
read -r -p "Super admin email: " SA_EMAIL
read -r -s -p "Super admin password: " SA_PASS; echo

PASS=0; FAIL=0
expect() {  # label expected actual
  if [ "$2" = "$3" ]; then echo "PASS  $1 ($3)"; PASS=$((PASS+1)); else echo "FAIL  $1: expected $2, got $3"; FAIL=$((FAIL+1)); fi
}
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))"; }

sa_body() { python3 -c "import sys,json; print(json.dumps({'email':sys.argv[1],'password':sys.argv[2]}))" "$SA_EMAIL" "$1"; }
sa_login() { curl -s -X POST "$BASE/platform-admin/login" -H 'Content-Type: application/json' -d "$(sa_body "$SA_PASS")"; }

echo; echo "--- 1. Platform login rate limit (5 per minute per email)"
codes=""
for i in 1 2 3 4 5 6; do
  codes="$codes $(code -X POST "$BASE/platform-admin/login" -H 'Content-Type: application/json' -d "$(sa_body 'definitely-wrong')")"
done
expect "6 wrong logins -> 401 x5 then 429" " 401 401 401 401 401 429" "$codes"
echo "(waiting 65s for the limit to clear)"; sleep 65

echo; echo "--- 2. Refresh, logout, logout-all"
LOGIN=$(sa_login)
ACCESS=$(echo "$LOGIN" | field access_token); REFRESH=$(echo "$LOGIN" | field refresh_token)
expect "login with real password" "200" "$(code "$BASE/platform-admin/galleries" -H "Authorization: Bearer $ACCESS")"

REFRESHED=$(curl -s -X POST "$BASE/platform-admin/refresh" -H "Authorization: Bearer $REFRESH")
NEW_ACCESS=$(echo "$REFRESHED" | field access_token)
expect "refresh returns a working access token" "200" "$(code "$BASE/platform-admin/galleries" -H "Authorization: Bearer $NEW_ACCESS")"

expect "logout" "200" "$(code -X POST "$BASE/platform-admin/logout" -H "Authorization: Bearer $NEW_ACCESS")"
expect "old access token dead after logout" "401" "$(code "$BASE/platform-admin/galleries" -H "Authorization: Bearer $ACCESS")"
expect "refresh token dead after logout" "401" "$(code -X POST "$BASE/platform-admin/refresh" -H "Authorization: Bearer $REFRESH")"

T1=$(sa_login | field access_token); T2=$(sa_login | field access_token)
expect "logout-all" "200" "$(code -X POST "$BASE/platform-admin/logout-all" -H "Authorization: Bearer $T1")"
expect "second session dead after logout-all" "401" "$(code "$BASE/platform-admin/galleries" -H "Authorization: Bearer $T2")"

echo; echo "--- 3. Uploads (as the curator of test-gallery-a)"
CUR=$(curl -s -X POST "$BASE/login" -H 'Content-Type: application/json' \
  -d '{"email":"curator@sandbox.test","password":"SandboxPass123!","org_slug":"test-gallery-a"}')
TOKEN=$(echo "$CUR" | field access_token)
ORG=$(echo "$CUR" | python3 -c "import sys,json; print(json.load(sys.stdin)['member']['organization_id'])")

TMP=$(mktemp -d)
python3 -c "import base64,sys; open(sys.argv[1],'wb').write(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='))" "$TMP/real.png"
echo "this is not an image" > "$TMP/fake.png"
echo "hello" > "$TMP/notes.txt"

UP=$(curl -s -X POST "$BASE/upload-image" -H "Authorization: Bearer $TOKEN" -F "file=@$TMP/real.png")
FILENAME=$(echo "$UP" | field filename)
echo "stored as: $FILENAME"
case "$FILENAME" in "$ORG"/*.png) expect "real PNG stored in gallery folder $ORG/<random>.png" "ok" "ok";; *) expect "real PNG stored in gallery folder $ORG/<random>.png" "ok" "got '$FILENAME'";; esac
expect "uploaded file can be fetched" "200" "$(code "$BASE/uploads/$FILENAME")"
expect "fake image (text named .png) rejected" "400" "$(code -X POST "$BASE/upload-image" -H "Authorization: Bearer $TOKEN" -F "file=@$TMP/fake.png")"
expect "disallowed extension (.txt) rejected" "400" "$(code -X POST "$BASE/upload-image" -H "Authorization: Bearer $TOKEN" -F "file=@$TMP/notes.txt")"
expect "upload without a token" "401" "$(code -X POST "$BASE/upload-image" -F "file=@$TMP/real.png")"

ART=$(curl -s -X POST "$BASE/artworks" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"title\":\"Upload check\",\"artist\":\"Tester\",\"image_path\":\"$FILENAME\"}")
ART_ID=$(echo "$ART" | python3 -c "import sys,json; print(json.load(sys.stdin).get('artwork',{}).get('id',''))")
expect "artwork with own gallery's image accepted" "201" "$(code -X POST "$BASE/artworks" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"title\":\"Upload check 2\",\"artist\":\"Tester\",\"image_path\":\"$FILENAME\"}")"
expect "artwork pointing at another gallery's folder rejected" "400" "$(code -X POST "$BASE/artworks" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"title":"Sneaky one","artist":"Tester","image_path":"2/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png"}')"
[ -n "$ART_ID" ] && curl -s -o /dev/null -X DELETE "$BASE/artworks/$ART_ID" -H "Authorization: Bearer $TOKEN" && echo "(cleaned up test artwork $ART_ID; the second one 'Upload check 2' is left in the sandbox)"

rm -rf "$TMP"
echo; echo "$PASS passed, $FAIL failed."