#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$0")"
pkill -f "deno run" 2>/dev/null
sleep 1
nohup deno run --allow-net --allow-env --allow-read --allow-write --env-file=.env main.ts > kimi.log 2>&1 &
disown
sleep 2
tail -n 3 kimi.log
