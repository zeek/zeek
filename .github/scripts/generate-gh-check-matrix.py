#!/usr/bin/env python3

import json
import os


def get_pr_labels():
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path:
        return []

    with open(event_path) as f:
        event_data = json.load(f)

    pr = event_data.get("pull_request", {})
    labels = [label["name"] for label in pr.get("labels", [])]
    return labels


def is_pr():
    return os.environ.get("GITHUB_EVENT_NAME") == "pull_request"


# skip_if conditionals (matching CircleCI filter logic):
#   FILTER_IF_SKIP_ALL: contains(... 'CI: Skip All')
#   FILTER_IF_PR_NOT_FULL_CI: Skip All OR (is PR and no Full label)
#   FILTER_IF_PR_NOT_FULL_OR_BENCHMARK: Skip All OR (is PR and no Full and no Benchmark)
#   FILTER_IF_PR_NOT_FULL_OR_ZAM: Skip All OR (is PR and no Full and no ZAM)
#   FILTER_IF_PR_NOT_FULL_OR_ZEEKCTL: Skip All OR (is PR and no Full and no Zeekctl)
#   Weekly/nightly builds: skip_if: true (no schedule trigger in this workflow)


def skip_if_skip_all(labels):
    """FILTER_IF_SKIP_ALL: Skip if skip_all is set."""
    return "CI: Skip All" in labels


def skip_if_pr_full(labels):
    """FILTER_IF_PR_NOT_FULL_CI: Skip if skip_all, or it's a PR without full."""
    if "CI: Skip All" in labels:
        return True
    if is_pr() and "CI: Full" not in labels:
        return True
    return False


def skip_if_pr_full_or_benchmark(labels):
    """FILTER_IF_PR_NOT_FULL_OR_BENCHMARK: Skip if skip_all, or it's a PR without full/benchmark."""
    if "CI: Skip All" in labels:
        return True
    if is_pr() and "CI: Full" not in labels and "CI: Benchmark" not in labels:
        return True
    return False


def skip_if_pr_full_or_cluster_test(labels):
    """FILTER_IF_PR_NOT_FULL_OR_CLUSTER_TEST: Skip if skip_all, or it's a PR without full/cluster_test."""
    if "CI: Skip All" in labels:
        return True
    if is_pr() and "CI: Full" not in labels and "CI: Cluster Testing" not in labels:
        return True
    return False


def skip_if_pr_full_or_zam(labels):
    """FILTER_IF_PR_NOT_FULL_OR_ZAM: Skip if skip_all, or it's a PR without full/zam."""
    if "CI: Skip All" in labels:
        return True
    if is_pr() and "CI: Full" not in labels and "CI: ZAM" not in labels:
        return True
    return False


def skip_if_pr_full_or_zeekctl(labels):
    """FILTER_IF_PR_NOT_FULL_OR_ZEEKCTL: Skip if skip_all, or it's a PR without full/zeekctl."""
    if "CI: Skip All" in labels:
        return True
    if is_pr() and "CI: Full" not in labels and "CI: Zeekctl" not in labels:
        return True
    return False


def nightly_or_tagged():
    """FILTER_NIGHTLY_OR_TAGGED: Run only for nightly schedules or release tags."""
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name == "schedule":
        return True
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/v"):
        return True
    return False


def add_job(
    includes: list[dict],
    id: str,
    file: str,
    skip: bool,
    config_flags: str = "",
    env_vars: dict = {},
    run_cmds: str = "",
):
    if skip:
        return

    if config_flags:
        env_vars["ZEEK_CI_CONFIGURE_FLAGS"] = config_flags

    job = {"id": id, "file": file, "env": env_vars}

    if run_cmds:
        job["run"] = run_cmds
    else:
        job["run"] = """
            ./ci/pre-build.sh
            ./ci/build.sh
            ./ci/test.sh"""

    includes.append(job)


includes = []
pr_labels = get_pr_labels()

# TODO: add missing jobs:
#   - container image building (but skip pushing to AWS-ECR/DockerHub)
#   - debian 13 ARM


add_job(
    includes,
    "fedora-43",
    "ci/fedora-43/Dockerfile",
    skip_if_pr_full(pr_labels),
    "--build-type=debug --disable-broker-tests --prefix=$ZEEK_CI_WORKING_DIR/install --ccache",
)

add_job(
    includes,
    "fedora-44",
    "ci/fedora-44/Dockerfile",
    skip_if_skip_all(pr_labels),
    "--build-type=debug --disable-broker-tests --prefix=$ZEEK_CI_WORKING_DIR/install --ccache",
)

add_job(
    includes,
    "centos-stream-9",
    "ci/centos-stream-9/Dockerfile",
    skip_if_pr_full(pr_labels),
)
add_job(
    includes,
    "centos-stream-10",
    "ci/centos-stream-10/Dockerfile",
    skip_if_pr_full(pr_labels),
)
add_job(includes, "debian-13", "ci/debian-13/Dockerfile", skip_if_pr_full(pr_labels))

add_job(
    includes,
    "debian-13-static",
    "ci/debian-13/Dockerfile",
    skip_if_pr_full(pr_labels),
    "--build-type=release --disable-broker-tests --enable-static-broker --enable-static-binpac --prefix=$ZEEK_CI_WORKING_DIR/install --ccache --enable-werror",
)

add_job(
    includes,
    "debian-13-binary",
    "ci/debian-13/Dockerfile",
    skip_if_pr_full(pr_labels),
    "--prefix=$ZEEK_CI_WORKING_DIR/install --libdir=$ZEEK_CI_WORKING_DIR/install/lib --binary-package --enable-static-broker --enable-static-binpac --disable-broker-tests --build-type=Release --ccache --enable-werror",
)

add_job(includes, "debian-12", "ci/debian-12/Dockerfile", skip_if_pr_full(pr_labels))
add_job(
    includes,
    "opensuse-leap-16.0",
    "ci/opensuse-leap-16.0/Dockerfile",
    skip_if_pr_full(pr_labels),
)
add_job(
    includes,
    "opensuse-tumbleweed",
    "ci/opensuse-tumbleweed/Dockerfile",
    skip_if_pr_full(pr_labels),
)

# TODO: These two builds shouldn't run all the time. They should be run off a weekly trigger.
add_job(
    includes,
    "weekly-current-gcc",
    "ci/debian-unstable/Dockerfile",
    skip_if_pr_full(pr_labels),
    "",
    {"ZEEK_CI_COMPILER": "gcc"},
    """./ci/debian-unstable/prepare-weekly.sh
       ./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh""",
)

add_job(
    includes,
    "weekly-current-clang",
    "ci/debian-unstable/Dockerfile",
    skip_if_pr_full(pr_labels),
    "",
    {"ZEEK_CI_COMPILER": "clang"},
    """./ci/debian-unstable/prepare-weekly.sh
       ./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh""",
)

add_job(
    includes, "ubuntu-26.04", "ci/ubuntu-26.04/Dockerfile", skip_if_pr_full(pr_labels)
)

add_job(
    includes,
    "ubuntu-24.04",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_skip_all(pr_labels),
    "",
    {"ZEEK_CI_CREATE_INSTALL_TARBALL": 1},
    """./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh
       ./ci/benchmark.sh""",
)

add_job(
    includes,
    "ubuntu-24.04-zam",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full_or_zam(pr_labels),
    "",
    {
        "ZEEK_CI_SKIP_UNIT_TESTS": 1,
        "ZEEK_CI_SKIP_EXTERNAL_BTESTS": 1,
        "ZEEK_CI_BTEST_EXTRA_ARGS": "-a zam",
        # Use a lower number of jobs due to OOM issues with ZAM tasks
        "ZEEK_CI_BTEST_JOBS": 3,
    },
)

add_job(
    includes,
    "ubuntu-24.04-clang-libcpp",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full(pr_labels),
    "",
    {
        "CC": "clang-19",
        "CXX": "clang++-19",
        "CXXFLAGS": "-stdlib=libc++",
        # The libnode package is linked with the system's libstdc++, making
        # it incompatible with Zeek compiled using libc++.
        "ZEEK_CI_CONFIGURE_FLAGS_EXTRA": "--disable-javascript",
    },
)

add_job(
    includes,
    "ubuntu-24.04-clang-tidy",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full(pr_labels),
    "--build-type=debug --disable-broker-tests --prefix=$ZEEK_CI_WORKING_DIR/install --ccache --enable-werror --enable-clang-tidy",
    {"CC": "clang-19", "CXX": "clang++-19"},
    """./ci/pre-build.sh
       ./ci/build.sh
       # Tests disabled for clang-tidy builds
    """,
)

add_job(
    includes,
    "ubuntu-24.04-spicy",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full_or_benchmark(pr_labels),
    "--build-type=release --disable-broker-tests --enable-spicy-ssl --prefix=$ZEEK_CI_WORKING_DIR/install --ccache --enable-werror",
    {"ZEEK_CI_CREATE_INSTALL_TARBALL": 1},
    """./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh
       ./ci/spicy-install-analyzers.sh""",
)

add_job(
    includes,
    "ubuntu-24.04-spicy-head",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full_or_benchmark(pr_labels),
    "--build-type=release --disable-broker-tests --enable-spicy-ssl --prefix=$ZEEK_CI_WORKING_DIR/install --ccache --enable-werror",
    {
        "ZEEK_CI_CREATE_INSTALL_TARBALL": 1,
        "ZEEK_CI_PREBUILD_COMMAND": "cd auxil/spicy && git fetch && git reset --hard origin/main && git submodule update --init --recursive",
    },
    """./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh
       ./ci/benchmark.sh""",
)

add_job(
    includes, "ubuntu-22.04", "ci/ubuntu-22.04/Dockerfile", skip_if_pr_full(pr_labels)
)
add_job(includes, "alpine", "ci/alpine/Dockerfile", skip_if_pr_full(pr_labels))

add_job(
    includes,
    "asan-sanitizer",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_skip_all(pr_labels),
    "--build-type=debug --disable-broker-tests --sanitizers=address --enable-fuzzers --enable-coverage --ccache --enable-werror",
    {
        "CXXFLAGS": "-DZEEK_DICT_DEBUG",
        "ASAN_OPTIONS": "detect_leaks=1:detect_odr_violation=0",
        # Use absolute paths for coverage files.
        "CCACHE_BASEDIR": "/",
    },
    """./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh
       ./ci/test-fuzzers.sh
       ./ci/upload-coverage.sh""",
)

add_job(
    includes,
    "asan-sanitizer-zam",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full_or_zam(pr_labels),
    "--build-type=debug --disable-broker-tests --sanitizers=address --ccache --enable-werror",
    {
        "ASAN_OPTIONS": "detect_leaks=1:detect_odr_violation=0",
        "ZEEK_CI_SKIP_UNIT_TESTS": 1,
        "ZEEK_CI_SKIP_EXTERNAL_BTESTS": 1,
        "ZEEK_CI_BTEST_EXTRA_ARGS": "-a zam",
        # Use a lower number of jobs due to OOM issues with ZAM tasks
        "ZEEK_CI_BTEST_JOBS": 3,
    },
)

add_job(
    includes,
    "ubsan-sanitizer",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full(pr_labels),
    "--build-type=debug --disable-broker-tests --sanitizers=undefined --enable-fuzzers --ccache --enable-werror",
    {
        "CC": "clang-19",
        "CXX": "clang++-19",
        "CXXFLAGS": "-DZEEK_DICT_DEBUG",
        "ZEEK_CI_CONFIGURE_FLAGS_EXTRA": "--disable-javascript",
        "ZEEK_TAILORED_UB_CHECKS": 1,
        "UBSAN_OPTIONS": "print_stacktrace=1",
    },
    """./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh
       ./ci/test-fuzzers.sh""",
)

add_job(
    includes,
    "ubsan-sanitizer-zam",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full_or_zam(pr_labels),
    "--build-type=debug --disable-broker-tests --sanitizers=undefined --enable-fuzzers --ccache --enable-werror",
    {
        "CC": "clang-19",
        "CXX": "clang++-19",
        "CXXFLAGS": "-DZEEK_DICT_DEBUG",
        "ZEEK_CI_CONFIGURE_FLAGS_EXTRA": "--disable-javascript",
        "ZEEK_TAILORED_UB_CHECKS": 1,
        "UBSAN_OPTIONS": "print_stacktrace=1",
        "ZEEK_CI_SKIP_UNIT_TESTS": 1,
        "ZEEK_CI_SKIP_EXTERNAL_BTESTS": 1,
        "ZEEK_CI_BTEST_EXTRA_ARGS": "-a zam",
        # Use a lower number of jobs due to OOM issues with ZAM tasks
        "ZEEK_CI_BTEST_JOBS": 3,
    },
    """./ci/pre-build.sh
       ./ci/build.sh
       ./ci/test.sh
       ./ci/test-fuzzers.sh""",
)

add_job(
    includes,
    "tsan-sanitizer",
    "ci/ubuntu-24.04/Dockerfile",
    skip_if_pr_full(pr_labels),
    "--build-type=debug --disable-broker-tests --sanitizers=thread --ccache --enable-werror",
    {
        "CC": "clang-19",
        "CXX": "clang++-19",
        "CXXFLAGS": "-DZEEK_DICT_DEBUG",
        "ZEEK_CI_CONFIGURE_FLAGS_EXTRA": "--disable-javascript",
        "ZEEK_CI_DISABLE_SCRIPT_PROFILING": 1,
        # If this is defined directly in the environment, configure fails to find
        # OpenSSL. Instead we define it with a different name and then give it
        # the correct name in the testing scripts.
        "ZEEK_TSAN_OPTIONS": "suppressions=/home/runner/work/zeek/zeek/ci/tsan_suppressions.txt",
    },
)

add_job(
    includes,
    "zeekctl-debian13",
    "ci/debian-13/Dockerfile",
    skip_if_pr_full_or_zeekctl(pr_labels),
    "",
    {},
    """apt-get update
       apt-get install -y --no-install-recommends iproute2
       cd auxil/zeekctl/testing
       ./Scripts/build-zeek
       ../../btest/btest -A -d -j ${ZEEK_CI_BTEST_JOBS}""",
)

add_job(
    includes,
    "include-plugins-debian13",
    "ci/debian-13/Dockerfile",
    skip_if_pr_full(pr_labels),
    "--include-plugins=${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/Files/protocol-plugin;${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/Files/py-lib-plugin;${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/Files/zeek-version-plugin;${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external/zeek-perf-support;${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external/zeek-more-hashes;${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external/zeek-cluster-backend-nats;${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external/zeek-kafka",
    {},
    """(cd ${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external && git clone https://github.com/zeek/zeek-perf-support.git)
       (cd ${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external && git clone https://github.com/zeek/zeek-more-hashes.git)
       (cd ${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external && git clone https://github.com/zeek/zeek-cluster-backend-nats.git)
       (cd ${ZEEK_CI_WORKING_DIR}/testing/builtin-plugins/external && git clone https://github.com/SeisoLLC/zeek-kafka.git)
       ./ci/build.sh
       (cd testing/builtin-plugins && ../../auxil/btest/btest -d -b -j ${ZEEK_CI_BTEST_JOBS})
       . ${ZEEK_CI_WORKING_DIR}/build/zeek-path-dev.sh
       set -ex
       # For now, just check if the external plugins are available.
       zeek -N Zeek::PerfSupport
       zeek -N Zeek::MoreHashes
       zeek -N Zeek::Cluster_Backend_NATS
       zeek -N Seiso::Kafka""",
)

matrix = {"include": includes}
print(json.dumps(matrix, separators=(",", ":")))
