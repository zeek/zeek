# Common material sourced by Bash CI scripts in this directory

# On Cirrus, oversubscribe the CPUs when on Linux or FreeBSD. This uses Cirrus' "greedy" feature.
if [[ "${CIRRUS_OS}" == linux || "${CIRRUS_OS}" == freebsd ]]; then
    if [[ -n "${ZEEK_CI_CPUS}" ]]; then
        ZEEK_CI_CPUS=$((2 * ${ZEEK_CI_CPUS}))
    fi

    if [[ -n "${ZEEK_CI_BTEST_JOBS}" ]]; then
        ZEEK_CI_BTEST_JOBS=$((2 * ${ZEEK_CI_BTEST_JOBS}))
    fi
fi
