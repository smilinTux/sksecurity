#!/usr/bin/env bash
# generate-manifest.sh — Generate INTEGRITY_MANIFEST.json for SKSecurity
# Creates SHA256 checksums of all key source files and optionally GPG-signs the manifest.
# Usage: ./scripts/generate-manifest.sh [--sign]
#
# Output:
#   INTEGRITY_MANIFEST.json       (always)
#   INTEGRITY_MANIFEST.json.sig   (if --sign and GPG key available)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${REPO_ROOT}/INTEGRITY_MANIFEST.json"
SIGN=false

for arg in "$@"; do
    case "$arg" in
        --sign) SIGN=true ;;
        --help|-h)
            echo "Usage: $0 [--sign]"
            echo "  --sign  GPG-sign the manifest (requires gpg + a secret key)"
            exit 0
            ;;
    esac
done

# Collect version from pyproject.toml
VERSION="unknown"
if [[ -f "${REPO_ROOT}/pyproject.toml" ]]; then
    VERSION=$(grep -m1 '^version' "${REPO_ROOT}/pyproject.toml" | sed 's/.*= *"\(.*\)"/\1/')
fi

# File patterns to include (relative to repo root)
# Covers: sksecurity/*.py, scripts/*.py, scripts/*.sh, setup.py, pyproject.toml, *.json configs at root
cd "$REPO_ROOT"

FILE_LIST=$(find \
    sksecurity -maxdepth 1 -name '*.py' 2>/dev/null; \
    find scripts -maxdepth 1 \( -name '*.py' -o -name '*.sh' \) 2>/dev/null; \
    for f in setup.py pyproject.toml package.json skill.yaml install.sh; do
        [[ -f "$f" ]] && echo "$f"
    done
) || true

if [[ -z "$FILE_LIST" ]]; then
    echo "ERROR: No files found to checksum." >&2
    exit 1
fi

# Sort for deterministic output
FILE_LIST=$(echo "$FILE_LIST" | sort -u)

# Build JSON
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOST=$(hostname -f 2>/dev/null || hostname)
FILE_COUNT=0

# Start JSON construction
{
    echo '{'
    echo "  \"version\": \"${VERSION}\","
    echo "  \"generated_at\": \"${GENERATED_AT}\","
    echo "  \"host\": \"${HOST}\","
    echo '  "files": {'

    FIRST=true
    while IFS= read -r filepath; do
        [[ -z "$filepath" ]] && continue
        [[ ! -f "$filepath" ]] && continue

        HASH=$(sha256sum "$filepath" | awk '{print $1}')
        SIZE=$(stat --printf='%s' "$filepath" 2>/dev/null || stat -f '%z' "$filepath" 2>/dev/null)

        if $FIRST; then
            FIRST=false
        else
            echo ','
        fi
        printf '    "%s": {"sha256": "%s", "size": %s}' "$filepath" "$HASH" "$SIZE"
        FILE_COUNT=$((FILE_COUNT + 1))
    done <<< "$FILE_LIST"

    echo ''
    echo '  },'
    echo "  \"file_count\": ${FILE_COUNT}"
    echo '}'
} > "$MANIFEST"

echo "Manifest generated: ${MANIFEST}"
echo "  Version:    ${VERSION}"
echo "  Files:      ${FILE_COUNT}"
echo "  Generated:  ${GENERATED_AT}"

# GPG signing
if $SIGN; then
    if ! command -v gpg &>/dev/null; then
        echo "WARNING: gpg not found, skipping signature." >&2
    else
        # Try to find a usable secret key
        GPG_KEY=$(gpg --list-secret-keys --keyid-format long 2>/dev/null | grep -m1 '^sec' | awk '{print $2}' | cut -d/ -f2)
        if [[ -z "$GPG_KEY" ]]; then
            echo "WARNING: No GPG secret key found, skipping signature." >&2
        else
            if timeout 10 gpg --detach-sign --armor --output "${MANIFEST}.sig" "$MANIFEST" 2>/dev/null; then
                echo "Signature:    ${MANIFEST}.sig (key: ${GPG_KEY})"
            else
                echo "WARNING: GPG signing failed (timeout or passphrase issue), skipping signature." >&2
                rm -f "${MANIFEST}.sig"
            fi
        fi
    fi
fi
