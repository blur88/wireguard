#!/usr/bin/env bash
set -euo pipefail

# Test cases that MUST be ignored by Git
ignored_cases=(
  ".env"
  ".env.local"
  ".env.production"
  ".DS_Store"
  "nested/folder/.DS_Store"
  "privatekey"
  "presharedkey"
  "wg0.key"
  "client.priv"
  "peer.psk"
  "wg_privatekey"
  "server_private_key"
  "wg0.conf"
  "nested/wg0.conf"
  "examples/client.key"
  "examples/.env"
)

# Test cases that MUST remain trackable (NOT ignored) by Git
tracked_cases=(
  ".env.example"
  "wg0.conf.example"
  "wg0.example.conf"
  "examples/wg0.conf.example"
  "examples/wg0.example.conf"
  "publickey"
  "wg0.pub"
  "src/main.go"
  "index.ts"
  "AGENTS.md"
  "README.md"
)

failed=0

for path in "${ignored_cases[@]}"; do
  if ! git check-ignore -q "$path"; then
    echo "FAIL: Expected $path to be ignored, but it was tracked."
    failed=1
  else
    echo "PASS (ignored): $path"
  fi
done

for path in "${tracked_cases[@]}"; do
  if git check-ignore -q "$path"; then
    echo "FAIL: Expected $path to be trackable, but it was ignored."
    failed=1
  else
    echo "PASS (trackable): $path"
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "Some verification checks failed."
  exit 1
fi

echo "All gitignore verification tests passed successfully!"
