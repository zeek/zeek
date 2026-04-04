#!/usr/bin/env sh

set -eu

ZEEK_RUST_MIN=1.74.0
RUSTUP_HOME_BIN="${HOME}/.cargo/bin"
RUSTUP_BIN="${RUSTUP_HOME_BIN}/rustup"
RUSTC_BIN="${RUSTUP_HOME_BIN}/rustc"
CARGO_BIN="${RUSTUP_HOME_BIN}/cargo"

version_lt() {
    left=$1
    right=$2

    left_major=${left%%.*}
    right_major=${right%%.*}
    left_rest=${left#*.}
    right_rest=${right#*.}
    left_minor=${left_rest%%.*}
    right_minor=${right_rest%%.*}
    left_patch=${left_rest#*.}
    right_patch=${right_rest#*.}

    if [ "${left_major}" -lt "${right_major}" ]; then
        return 0
    fi

    if [ "${left_major}" -gt "${right_major}" ]; then
        return 1
    fi

    if [ "${left_minor}" -lt "${right_minor}" ]; then
        return 0
    fi

    if [ "${left_minor}" -gt "${right_minor}" ]; then
        return 1
    fi

    [ "${left_patch}" -lt "${right_patch}" ]
}

rustc_version() {
    "$1" --version | awk '{print $2}'
}

have_supported_system_toolchain() {
    command -v cargo >/dev/null 2>&1 || return 1
    command -v rustc >/dev/null 2>&1 || return 1

    current_version=$(rustc_version "$(command -v rustc)")
    ! version_lt "${current_version}" "${ZEEK_RUST_MIN}"
}

install_curl_if_needed() {
    command -v curl >/dev/null 2>&1 && return 0

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y curl
        return 0
    fi

    if command -v dnf >/dev/null 2>&1; then
        dnf -y install curl
        return 0
    fi

    if command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install curl
        return 0
    fi

    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl
        return 0
    fi

    if command -v pkg >/dev/null 2>&1; then
        env ASSUME_ALWAYS_YES=YES pkg install -y curl
        return 0
    fi

    echo "error: curl is required to install the Rust toolchain in CI" >&2
    exit 1
}

install_or_update_rustup() {
    install_curl_if_needed

    if [ ! -x "${RUSTUP_BIN}" ]; then
        curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal \
            --default-toolchain stable
        return 0
    fi

    "${RUSTUP_BIN}" toolchain install stable --profile minimal
    "${RUSTUP_BIN}" default stable
}

if have_supported_system_toolchain; then
    cargo --version
    rustc --version
    exit 0
fi

install_or_update_rustup

PATH="${RUSTUP_HOME_BIN}:${PATH}"
export PATH

if [ ! -x "${CARGO_BIN}" ] || [ ! -x "${RUSTC_BIN}" ]; then
    echo "error: rustup did not install cargo/rustc into ${RUSTUP_HOME_BIN}" >&2
    exit 1
fi

current_version=$(rustc_version "${RUSTC_BIN}")

if version_lt "${current_version}" "${ZEEK_RUST_MIN}"; then
    echo "error: installed rustc ${current_version}, but Zeek CI requires ${ZEEK_RUST_MIN} or newer" >&2
    exit 1
fi

"${CARGO_BIN}" --version
"${RUSTC_BIN}" --version
