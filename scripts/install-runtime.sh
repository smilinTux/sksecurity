#!/usr/bin/env bash
set -euo pipefail

repo_dir="${SKSECURITY_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
venv_dir="${SKSECURITY_VENV:-${HOME}/.venvs/sksecurity}"
python_bin="${SKSECURITY_PYTHON:-}"

if [[ -z "${python_bin}" ]]; then
    for candidate in "${venv_dir}/bin/python" "${HOME}/.venvs/skops/bin/python" python3.12 python3; do
        if [[ "${candidate}" == */* && -x "${candidate}" ]] || command -v "${candidate}" >/dev/null 2>&1; then
            python_bin="${candidate}"
            break
        fi
    done
fi

if [[ -z "${python_bin}" ]]; then
    printf 'no supported Python interpreter found; set SKSECURITY_PYTHON\n' >&2
    exit 1
fi

"${python_bin}" -m venv "${venv_dir}"
"${venv_dir}/bin/python" -m pip install --upgrade pip
"${venv_dir}/bin/python" -m pip install -e "${repo_dir}[web,pdf,skcapstone]"
"${venv_dir}/bin/python" -m pip check
"${venv_dir}/bin/sksecurity" --help >/dev/null

mkdir -p "${HOME}/.local/bin"
ln -sfn "${venv_dir}/bin/sksecurity" "${HOME}/.local/bin/sksecurity"
ln -sfn "${venv_dir}/bin/sksecurity-mcp" "${HOME}/.local/bin/sksecurity-mcp"

printf 'sksecurity runtime ready: %s\n' "${venv_dir}"
