"""Upload a verified SentinelAI backup pair to a private S3 bucket.

Uses the standard boto3 credential chain (normally a dedicated named profile).
No credentials are accepted on the command line or written to logs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


STAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")
ARTIFACTS = (("database_file", "database_sha256"), ("app_data_file", "app_data_sha256"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_artifact(backup_dir: Path, manifest: dict, filename_field: str, hash_field: str) -> tuple[Path, str]:
    filename = manifest.get(filename_field)
    expected_hash = manifest.get(hash_field)
    if not isinstance(filename, str) or Path(filename).name != filename or filename in {".", ".."}:
        raise ValueError(f"Invalid artifact filename in manifest field {filename_field}.")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
        raise ValueError(f"Invalid SHA-256 value in manifest field {hash_field}.")
    path = (backup_dir / filename).resolve(strict=True)
    if backup_dir.resolve() not in path.parents:
        raise ValueError("Backup artifact resolves outside the local backup directory.")
    actual_hash = sha256_file(path)
    if actual_hash != expected_hash.lower():
        raise ValueError(f"SHA-256 verification failed for {filename}; nothing was uploaded.")
    return path, actual_hash


def existing_object_matches(
    s3, bucket: str, key: str, digest: str, size: int, *, forbidden_means_absent: bool = False
) -> bool:
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code", ""))
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in {"404", "NoSuchKey", "NotFound"} or status == 404:
            return False
        # The writer identity deliberately lacks s3:ListBucket, so S3 answers 403
        # (not 404) for a key that does not exist. Before an upload that is treated
        # as "absent": an existing object would be readable through s3:GetObject and
        # return 200, and a real permission problem still fails the upload itself.
        # After an upload a 403 is never accepted.
        if forbidden_means_absent and (code in {"403", "AccessDenied", "Forbidden"} or status == 403):
            return False
        raise
    metadata = head.get("Metadata", {})
    if metadata.get("sha256") != digest or head.get("ContentLength") != size:
        raise ValueError(f"Remote object already exists with different content: s3://{bucket}/{key}")
    if head.get("ServerSideEncryption") != "AES256":
        raise ValueError(f"Remote object is not encrypted with SSE-S3: s3://{bucket}/{key}")
    return True


def upload(s3, bucket: str, prefix: str, path: Path, digest: str) -> str:
    key = f"{prefix}/{path.name}"
    if existing_object_matches(s3, bucket, key, digest, path.stat().st_size, forbidden_means_absent=True):
        print(f"Already present and verified: s3://{bucket}/{key}")
        return key
    content_type = "application/json" if path.suffix.lower() == ".json" else "application/octet-stream"
    s3.upload_file(
        str(path),
        bucket,
        key,
        ExtraArgs={
            "ServerSideEncryption": "AES256",
            "ContentType": content_type,
            "Metadata": {"sha256": digest},
        },
    )
    if not existing_object_matches(s3, bucket, key, digest, path.stat().st_size):
        raise RuntimeError(f"S3 did not return the uploaded object: s3://{bucket}/{key}")
    print(f"Uploaded and verified: s3://{bucket}/{key}")
    return key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", type=Path, default=Path(__file__).resolve().parents[1] / "backups")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", help="AWS shared-config profile; omit to use the default boto3 credential chain.")
    args = parser.parse_args()

    try:
        backup_dir = args.backup_dir.resolve(strict=True)
        manifest_path = args.manifest.resolve(strict=True)
        if backup_dir not in manifest_path.parents:
            raise ValueError("Manifest must be stored under the local backup directory.")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        stamp = manifest.get("created_at")
        if not isinstance(stamp, str) or not STAMP_RE.fullmatch(stamp):
            raise ValueError("Manifest created_at must use the UTC format YYYYMMDDTHHMMSSZ.")
        prepared = []
        for filename_field, hash_field in ARTIFACTS:
            path, digest = checked_artifact(backup_dir, manifest, filename_field, hash_field)
            prepared.append((path, digest))
        prepared.append((manifest_path, sha256_file(manifest_path)))

        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        s3 = session.client("s3", region_name=args.region)
        prefix = f"sentinelai-xdr/{stamp}"
        # Upload the manifest last so it acts as a commit marker for complete pairs.
        for path, digest in prepared:
            upload(s3, args.bucket, prefix, path, digest)
        print(f"Off-site backup complete: s3://{args.bucket}/{prefix}/")
        return 0
    except NoCredentialsError:
        print("AWS credentials were not found. Configure a dedicated least-privilege backup profile; do not paste keys here.", file=sys.stderr)
    except (BotoCoreError, ClientError, OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"Off-site backup failed: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
