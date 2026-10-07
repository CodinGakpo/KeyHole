#!/bin/sh
# Run terraform for this environment against the keyhole AWS account (162663626031, us-east-1).
#
# Loads AWS_ACCESS_KEY / AWS_SECRET_KEY from the repo-root .env (parsed, never sourced — the file
# is not a clean shell script) so the keys stay off the command line, and so the default ~/.aws
# profile (a guarded, unrelated account) is never used. Always runs from this directory.
#
# Usage (from anywhere):  infra/terraform/environments/dev/tf.sh plan|apply|destroy [args...]
set -eu

here=$(cd "$(dirname "$0")" && pwd -P)
env_file="$here/../../../../.env"

get() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p" "$env_file" | head -n 1; }

AWS_ACCESS_KEY_ID=$(get AWS_ACCESS_KEY)
AWS_SECRET_ACCESS_KEY=$(get AWS_SECRET_KEY)
[ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ] || {
    echo "tf.sh: AWS_ACCESS_KEY / AWS_SECRET_KEY not found in $env_file" >&2
    exit 1
}
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
unset AWS_PROFILE

cd "$here"
exec terraform "$@"
