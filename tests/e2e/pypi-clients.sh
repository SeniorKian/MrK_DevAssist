#!/bin/sh
set -eu

index_url="${1:?PyPI simple index URL is required}"
trusted_host="${2:-127.0.0.1}"
work_dir="$(mktemp -d)"
export HOME="$work_dir/home"
export PIP_DISABLE_PIP_VERSION_CHECK=1
export POETRY_VIRTUALENVS_IN_PROJECT=true
mkdir -p "$HOME" "$work_dir/poetry-project"

python -m pip install --no-cache-dir uv==0.13.7 poetry==2.5.1

python -m pip download \
    --no-deps \
    --dest "$work_dir/pip-download" \
    --index-url "$index_url" \
    --trusted-host "$trusted_host" \
    sampleproject==4.0.0

uv pip install \
    --system \
    --allow-insecure-host "$trusted_host" \
    --index-url "$index_url" \
    sampleproject==4.0.0

cd "$work_dir/poetry-project"
poetry init --name mrk-pypi-e2e --no-interaction
poetry source add --priority=primary mrk "$index_url"
poetry add sampleproject==4.0.0 --no-interaction
poetry run python -c "import sample; print('Poetry client OK:', sample.__file__)"

echo "pip, uv and Poetry clients completed successfully."
