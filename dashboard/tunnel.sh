#!/bin/sh
# Give the dashboard a public HTTPS address with a free Cloudflare quick tunnel.
#
# Browsers only allow push notifications on HTTPS pages (localhost excepted),
# so this is what lets phones subscribe. The Pico keeps posting to the laptop
# over the local network; only browsers use the tunnel.
#
#   brew install cloudflared        (once)
#   python3 server.py --host 0.0.0.0
#   ./tunnel.sh                     (in another terminal; prints the https://...trycloudflare.com link)
#
# The link is new every time this script starts. Keep this terminal open for as
# long as the link should work.

PORT="${1:-8080}"
command -v cloudflared >/dev/null 2>&1 || { echo "cloudflared not found: brew install cloudflared"; exit 1; }
echo "Opening a tunnel to http://localhost:$PORT ..."
exec cloudflared tunnel --no-autoupdate --url "http://localhost:$PORT" 2>&1 | while IFS= read -r line; do
  case "$line" in
    *trycloudflare.com*)
      url=$(printf '%s\n' "$line" | grep -o 'https://[a-zA-Z0-9.-]*trycloudflare.com')
      [ -n "$url" ] && printf '\n  Dashboard link:  %s\n  Student portal:  %s/me.html\n\n' "$url" "$url" ;;
    *ERR*|*error*) printf '%s\n' "$line" ;;
  esac
done
