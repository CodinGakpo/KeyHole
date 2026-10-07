#!/bin/sh
# One-command on/off for the full cloud stack (keyhole account 162663626031, us-east-1).
#
#   up   = build the Lambda zip, terraform apply (control plane on), push the sandbox image to ECR,
#          then print the API endpoint and write the KMS public key to /tmp/kms.pem
#   down = terraform destroy everything
#
# Credentials come from the repo-root .env exactly as in tf.sh (parsed, never sourced).
# Usage (from anywhere):  infra/terraform/environments/dev/stack.sh up|down
set -eu

here=$(cd "$(dirname "$0")" && pwd -P)
repo="$here/../../../.."
env_file="$repo/.env"

get() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p" "$env_file" | head -n 1; }

AWS_ACCESS_KEY_ID=$(get AWS_ACCESS_KEY)
AWS_SECRET_ACCESS_KEY=$(get AWS_SECRET_KEY)
[ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ] || {
    echo "stack.sh: AWS_ACCESS_KEY / AWS_SECRET_KEY not found in $env_file" >&2
    exit 1
}
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
unset AWS_PROFILE

# The Lambda resource hashes this zip whenever the config is evaluated, so destroy needs it too.
[ -f "$repo/dist/controlplane.zip" ] || (cd "$repo" && .venv/bin/python scripts/build_lambda.py)

cd "$here"
case "${1:-}" in
up)
    (cd "$repo" && .venv/bin/python scripts/build_lambda.py)
    terraform apply -auto-approve -var enable_control_plane=true

    repo_url=$(terraform output -raw sandbox_repo_url)
    aws ecr get-login-password | docker login --username AWS --password-stdin "${repo_url%%/*}"
    docker build -t "${repo_url}:latest" "$repo/images/sandbox-python"
    docker push "${repo_url}:latest"

    aws kms get-public-key --key-id "$(terraform output -raw kms_key_id)" \
        --query PublicKey --output text | base64 -d \
        | openssl pkey -pubin -inform DER -outform PEM > /tmp/kms.pem
    echo
    echo "UP. Costs ~\$0.03/h and the API is unauthenticated; run 'stack.sh down' when done."
    echo "  export KEYHOLE_API_ENDPOINT=$(terraform output -raw api_endpoint)"
    echo "  verify cloud attestations with: --pubkey /tmp/kms.pem"
    ;;
down)
    terraform destroy -auto-approve -var enable_control_plane=true
    echo "DOWN."
    ;;
*)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
