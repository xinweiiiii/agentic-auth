#!/usr/bin/env bash
# usage: enroll.sh <agent-name>   (needs CP, A, H, AA4_DIR and the venv on PATH)
set -euo pipefail
N=$1
ID=$(curl -sS $CP/v1/agents -H "Authorization: Bearer dev-admin-token" | jq -r ".data[] | select(.name==\"$N\") | .id")
ASSERT=$(curl -sS "127.0.0.1:9100/mint?agent=$N" | jq -r .id_token)
agentic-auth identity identity-document --key $AA4_DIR/keys/$N.pem --agent $N --principal-assertion "$ASSERT" > $AA4_DIR/doc-$N.json
curl -sS -X POST $CP/v1/agents/$ID/enroll -H "$A" -H "$H" -d @$AA4_DIR/doc-$N.json > $AA4_DIR/ch-$N.json
SIG=$(agentic-auth identity sign-challenge --key $AA4_DIR/keys/$N.pem --agent $N --challenge $AA4_DIR/ch-$N.json)
curl -sS -X POST $CP/v1/agents/$ID/enroll/complete -H "$A" -H "$H" \
  -d "{\"challenge_id\":\"$(jq -r .challenge_id $AA4_DIR/ch-$N.json)\",\"signed_response\":\"$SIG\"}" | jq -c "{agent: \"$N\", status, trust_anchor_version}"
