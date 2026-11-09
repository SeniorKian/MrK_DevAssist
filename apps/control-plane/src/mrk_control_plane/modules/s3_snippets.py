"""Copy-ready client configuration snippets (docs/30 appendix A)."""

from __future__ import annotations

from urllib.parse import urlsplit

AKID_PLACEHOLDER = "<ACCESS_KEY_ID>"
SECRET_PLACEHOLDER = "<SECRET_ACCESS_KEY>"  # noqa: S105 - placeholder
BUCKET_PLACEHOLDER = "<bucket>"


def connection_snippets(
    endpoint: str,
    region: str,
    *,
    bucket: str | None = None,
    access_key_id: str | None = None,
) -> dict[str, str]:
    """Snippets never contain a real secret: the panel shows the secret only once, at creation."""
    akid = access_key_id or AKID_PLACEHOLDER
    secret = SECRET_PLACEHOLDER
    target = bucket or BUCKET_PLACEHOLDER
    host = urlsplit(endpoint).netloc
    return {
        "aws_cli": (
            f"aws configure set aws_access_key_id {akid}\n"
            f"aws configure set aws_secret_access_key '{secret}'\n"
            f"aws configure set region {region}\n"
            "aws configure set default.s3.addressing_style path\n"
            f"aws --endpoint-url {endpoint} s3 ls s3://{target}/\n"
        ),
        "rclone": (
            "[mrk]\n"
            "type = s3\n"
            "provider = Other\n"
            f"access_key_id = {akid}\n"
            f"secret_access_key = {secret}\n"
            f"endpoint = {endpoint}\n"
            f"region = {region}\n"
            "force_path_style = true\n"
            "acl = private\n"
        ),
        "mc": (
            f"mc alias set mrk {endpoint} {akid} '{secret}' --api S3v4 --path on\n"
            f"mc ls mrk/{target}\n"
        ),
        "boto3": (
            "import boto3\n"
            "from botocore.config import Config\n"
            f's3 = boto3.client("s3", endpoint_url="{endpoint}", region_name="{region}",\n'
            f'                  aws_access_key_id="{akid}", aws_secret_access_key="{secret}",\n'
            '                  config=Config(s3={"addressing_style": "path"}, '
            'signature_version="s3v4"))\n'
            f's3.list_objects_v2(Bucket="{target}")\n'
        ),
        "restic": (
            f"export AWS_ACCESS_KEY_ID={akid}\n"
            f"export AWS_SECRET_ACCESS_KEY='{secret}'\n"
            f"export AWS_DEFAULT_REGION={region}\n"
            f"restic -r s3:{endpoint}/{target}/restic init\n"
        ),
        "dokploy": (
            "Dokploy -> Settings -> S3 Destinations -> Add\n"
            "Name: DevAssist\n"
            f"Access Key: {akid}\n"
            f"Secret Key: {secret}\n"
            f"Bucket: {target}\n"
            f"Region: {region}\n"
            f"Endpoint: {endpoint}\n"
            "Provider: none/Other -> Test\n"
        ),
        "s3cmd": (
            f"host_base = {host}\n"
            f"host_bucket = {host}\n"
            f"use_https = {'True' if endpoint.startswith('https://') else 'False'}\n"
            "signature_v2 = False\n"
            f"bucket_location = {region}\n"
        ),
    }


COMPOSE_HINT = """\
# Add a host folder to the MRK service (compose.yaml), then: docker compose up -d
services:
  mrk:
    volumes:
      # Recommended: one parent mount; every sub-folder can become its own bucket
      # without another restart.
      - /srv/mrk-share:/mnt/links
      # Or a single folder, read-only:
      # - /srv/files:/mnt/links/files:ro
# MRK runs as UID 10001. For read-write links grant access on the host:
#   sudo setfacl -R -m u:10001:rwX -m d:u:10001:rwX /srv/mrk-share
"""
