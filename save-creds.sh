#!/data/data/com.termux/files/usr/bin/bash
# Usage: pbpaste | save-creds.sh   (or: save-creds.sh < curl.txt)
set -e
SRC=$(cat)
STORE="$HOME/cookies/kimi-creds.json"

JWT=$(printf '%s' "$SRC" | grep -oE "Bearer eyJ[A-Za-z0-9._-]+" | head -1 | sed 's/^Bearer //')
COOKIES=$(printf '%s' "$SRC" | grep -oE "cookie: [^']+" | head -1 | sed "s/^cookie: //")
SHIELD=$(printf '%s' "$SRC" | grep -oE "x-msh-shield-data: sg:[A-Za-z0-9]+" | head -1 | sed 's/^x-msh-shield-data: //')
CHATID=$(printf '%s' "$SRC" | grep -oE '"chat_id":"[^"]+"' | head -1 | sed 's/"chat_id":"//;s/"$//')
PARENT=$(printf '%s' "$SRC" | grep -oE '"parent_id":"[^"]+"' | head -1 | sed 's/"parent_id":"//;s/"$//')
DEVICE=$(printf '%s' "$SRC" | grep -oE "x-msh-device-id: [0-9]+" | head -1 | sed 's/^x-msh-device-id: //')
SESSION=$(printf '%s' "$SRC" | grep -oE "x-msh-session-id: [0-9]+" | head -1 | sed 's/^x-msh-session-id: //')
TRAFFIC=$(printf '%s' "$SRC" | grep -oE "x-traffic-id: [a-z0-9]+" | head -1 | sed 's/^x-traffic-id: //')

[ -z "$JWT" ] && { echo "no JWT found in input"; exit 1; }

python3 - "$STORE" "$JWT" "$COOKIES" "$SHIELD" "$CHATID" "$PARENT" "$DEVICE" "$SESSION" "$TRAFFIC" <<'PY'
import json, os, sys, time
p, jwt, ck, sh, cid, pid, dev, ses, tr = sys.argv[1:10]
d = json.load(open(p)) if os.path.exists(p) else {}
if jwt:   d["bearerToken"] = jwt
if ck:    d["cookies"]     = ck
if sh:    d["extraHeaders"] = {"x-msh-shield-data": sh}
if cid:   d["chatId"]      = cid
if pid:   d["parentId"]    = pid
if dev:   d["deviceId"]    = dev
if ses:   d["sessionId"]   = ses
if tr:    d["trafficId"]   = tr
d["acquiredAt"] = int(time.time() * 1000)
json.dump(d, open(p, "w"), indent=2)
print("saved: jwt_segs=%d cookies=%d shield=%s chat=%s parent=%s" % (
    d.get("bearerToken","").count(".")+1,
    len(d.get("cookies","")),
    bool(d.get("extraHeaders",{}).get("x-msh-shield-data")),
    bool(d.get("chatId")), bool(d.get("parentId"))))
PY
