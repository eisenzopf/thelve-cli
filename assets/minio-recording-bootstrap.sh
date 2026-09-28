#!/bin/sh
# Run in a one-off MinIO provisioning container with protected credential mounts.
# The installer must supply a dedicated client pair, not the MinIO root pair.
set -eu
umask 077

fail() { printf '%s\n' 'Bundled recording storage provisioning failed.' >&2; exit 1; }
for credential_file in "${MINIO_ROOT_USER_FILE:-}" "${MINIO_ROOT_PASSWORD_FILE:-}" "${AWS_ACCESS_KEY_ID_FILE:-}" "${AWS_SECRET_ACCESS_KEY_FILE:-}"; do
    [ -f "$credential_file" ] && [ ! -L "$credential_file" ] && [ -r "$credential_file" ] && [ -s "$credential_file" ] || fail
done
client_access=$(cat "$AWS_ACCESS_KEY_ID_FILE")
case "$client_access" in ''|*[!a-zA-Z0-9_-]*) fail ;; esac
[ "${#client_access}" -le 128 ] || fail
root_access=$(cat "$MINIO_ROOT_USER_FILE")
[ "$client_access" != "$root_access" ] || fail
unset root_access

config_dir=$(mktemp -d /tmp/thelve-recording-bootstrap.XXXXXX) || fail
trap 'rm -rf "$config_dir"' EXIT
trap 'exit 1' HUP INT TERM
export MC_CONFIG_DIR="$config_dir"

# mc supports piped credentials. Neither key appears in its process arguments.
{ printf '%s\n' "$(cat "$MINIO_ROOT_USER_FILE")" "$(cat "$MINIO_ROOT_PASSWORD_FILE")"; } |
    mc alias set appliance http://minio:9000 --api S3v4 --path on >/dev/null 2>&1 || fail
mc mb --ignore-existing appliance/thelve-objects >/dev/null 2>&1 || fail
{ printf '%s\n' "$client_access" "$(cat "$AWS_SECRET_ACCESS_KEY_FILE")"; } |
    mc admin user add appliance >/dev/null 2>&1 || fail

# The single-node API uses this one account for recordings, attachments,
# exports, imports, evaluation audio, coworker publication snapshots and the
# other governed objects, exactly as the portable appliance does. Limit it to
# the appliance bucket rather than to a list of prefixes that every new
# object kind would have to be added to.
cat > "$config_dir/recordings-policy.json" <<'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket","s3:ListBucketMultipartUploads"],"Resource":["arn:aws:s3:::thelve-objects"]},
    {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::thelve-objects/*"]}
  ]
}
POLICY
mc admin policy create appliance thelve-recording-storage "$config_dir/recordings-policy.json" >/dev/null 2>&1 || fail
mc admin policy attach appliance thelve-recording-storage --user "$client_access" >/dev/null 2>&1 || fail
