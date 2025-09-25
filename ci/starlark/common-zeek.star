"""
A collection of functions for creating Zeek builds. This includes configure options,
directives for 'skip' and 'only_if', environment setup, and the CI template.
"""

load("github.com/cirrus-modules/helpers", "always", "artifacts", "cache", "on_failure", "script")

############################################
# Rules for setting options to `configure`
############################################

def _configure_opt_default(build_type):
    return "--build-type=" + build_type + " --disable-broker-tests --prefix=$CIRRUS_WORKING_DIR/install --ccache --enable-werror -D FETCHCONTENT_FULLY_DISCONNECTED:BOOL=ON"

def configure_opt_default_release():
    return _configure_opt_default("release")

def configure_opt_default_debug():
    return _configure_opt_default("debug")

def configure_opt_no_spicy():
    return configure_opt_default_release() + "--disable-spicy"

def configure_opt_static():
    return configure_opt_default_release() + "--enable-static-broker --enable-static-binpac"

def configure_opt_binary():
    return configure_opt_default_release() + "--enable-static-broker --enable-static-binpac --libdir=$CIRRUS_WORKING_DIR/install/lib --binary-package"

def configure_opt_spicy_ssl():
    return configure_opt_default_release() + "--enable-spicy-ssl"

def configure_opt_asan():
    return configure_opt_default_debug() + "--sanitizers=address --enable-fuzzers --enable-coverage"

def configure_opt_ubsan():
    return configure_opt_default_debug() + "--sanitizers=undefined"

def configure_opt_tsan():
    return configure_opt_default_debug() + "--sanitizers=thread"

def configure_opt_macos():
    return configure_opt_default_release() + "--with-krb5=/opt/homebrew/opt/krb5"

def configure_opt_clang_tidy():
    return configure_opt_default_debug() + "--enable-clang-tidy"

############################################
# Rules to pass to `only_if` directives
############################################

# TODO: It feels like there should be a better way to structure these so they aren't just
# blocks of strings.

def _only_if_valid_repo():
    return "( $CIRRUS_REPO_NAME == 'zeek' || $CIRRUS_REPO_NAME == 'zeek-security' )"

def _only_if_cron_not_weekly():
    return "( $CIRRUS_CRON != 'weekly' )"

def only_if_pr_master_or_release():
    return "( " + _only_if_valid_repo() + " && " + _only_if_cron_not_weekly() + """ &&
              ( $CIRRUS_PR != '' ||
                $CIRRUS_BRANCH == 'master' ||
                $CIRRUS_BRANCH =~ 'release/.*'
              )
            )"""

def only_if_pr_master_release_nightly():
    return "( " + _only_if_valid_repo() + " && " + _only_if_cron_not_weekly() + """ &&
              ( $CIRRUS_PR != '' ||
                $CIRRUS_BRANCH == 'master' ||
                $CIRRUS_BRANCH =~ 'release/.*' ||
                ( $CIRRUS_CRON == 'nightly' && $CIRRUS_BRANCH == 'master' )
              )
            )"""

def only_if_pr_release_and_nightly():
    return "( " + _only_if_valid_repo() + " && " + _only_if_cron_not_weekly() + """ &&
              ( $CIRRUS_PR != '' ||
                $CIRRUS_BRANCH =~ 'release/.*' ||
                ( $CIRRUS_CRON == 'nightly' && $CIRRUS_BRANCH == 'master' )
              )
            )"""

def only_if_pr_nightly():
    return "( " + _only_if_valid_repo() + " && " + _only_if_cron_not_weekly() + """ &&
              ( $CIRRUS_PR != '' ||
                ( $CIRRUS_CRON == 'nightly' && $CIRRUS_BRANCH == 'master' )
              )
            )"""

def only_if_release_tag_nightly():
    return "( " + _only_if_valid_repo() + " && " + _only_if_cron_not_weekly() + """ &&
                ( ( $CIRRUS_BRANCH =~ 'release/.*' && $CIRRUS_TAG =~ 'v[0-9]+\\.[0-9]+\\.[0-9]+(-rc[0-9]+)?$' ) ||
                  ( $CIRRUS_CRON == 'nightly' && $CIRRUS_BRANCH == 'master' )
                )
              )"""

def only_if_nightly():
    return "( " + _only_if_valid_repo() + """ &&
                ( $CIRRUS_CRON == 'nightly' && $CIRRUS_BRANCH == 'master' )
              )"""

def only_if_weekly():
    return "( " + _only_if_valid_repo() + """ &&
              ( $CIRRUS_CRON == 'weekly' && $CIRRUS_BRANCH == 'master' )
            )"""

############################################
# Rules to pass to `skip` directives
############################################

def _if_not_labeled_pr(label):
    return "( $CIRRUS_PR != '' && $CIRRUS_PR_LABELS != '.*CI: " + label + ".*' )"

def _if_skip_all_label():
    return "( $CIRRUS_PR_LABELS =~ '.*CI: Skip All.*' )"

def skip_if_pr_skip_all():
    return "$CIRRUS_PR != '' && " + _if_skip_all_label()

def skip_if_pr_not_full_ci():
    return _if_not_labeled_pr("Full") + " || " + _if_skip_all_label()

def skip_if_pr_not_full_or_benchmark():
    return _if_not_labeled_pr("(Full|Benchmark)") + " || " + _if_skip_all_label()

def skip_if_pr_not_full_or_cluster_test():
    return _if_not_labeled_pr("(Full|Cluster Test)") + " || " + _if_skip_all_label()

def skip_if_pr_not_full_or_zam():
    return _if_not_labeled_pr("(Full|ZAM)") + " || " + _if_skip_all_label()

def skip_if_pr_not_full_or_zeekctl():
    return _if_not_labeled_pr("(Full|Zeekctl)") + " || " + _if_skip_all_label()

def skip_if_pr_not_full_or_windows():
    return _if_not_labeled_pr("(Full|Windows)") + " || " + _if_skip_all_label()

############################################
# Default and platform-specific environments
############################################

def default_environment(config_opts):
    return {
        "CIRRUS_WORKING_DIR": "/zeek",
        "CIRRUS_LOG_TIMESTAMP": True,
        "ZEEK_CI_CPUS": 4,  # TODO based on resources()? based on result of *_environment()? taken as argument?
        "ZEEK_CI_BTEST_JOBS": 4,
        "ZEEK_CI_BTEST_RETRIES": 2,
        "ZEEK_CI_CONFIGURE_FLAGS": config_opts,

        # This is a single-purpose, read-only GitHub deploy key (SSH private key) for the
        # zeek-testing-private repository.
        #        "ZEEK_TESTING_PRIVATE_SSH_KEY": "ENCRYPTED[!dbdba93df9c166f926480cebff52dab303589257b3b3ee53aa392021aff2881ed9aafefef26aa9a1b71a49d663d1361c!]",

        # This is the key used to create HMAC auth keys for the benchmark script. This was
        # generated by creating a new key using openssl, and then running sha256 on it.
        #        "ZEEK_BENCHMARK_HMAC_KEY": "ENCRYPTED[!468e2f3ea05543c4d24eb6c776c0c10695b24faec3a11d22c8da99e1df0d5b56da5b705887b1c038962a7db3eae0b9a4!]",

        # This is the https endpoint host and port used for benchmarking. It's kept
        # encrypted as a security measure to avoid leaking the host's information.
        #        "ZEEK_BENCHMARK_HOST": "ENCRYPTED[!bcda5b49af0825ee5581b27f6a86106a15605a434c9c52827eb21eade8210e668af0456d14fffbe76c098cd2d30f5d48!]",
        #        "ZEEK_BENCHMARK_PORT": "ENCRYPTED[!793057d6d8a5d1ebb5e0392786e53cf81a2ff5adb1f5386b6c8914d2bf0c4d2ead09e8f3c08c\"28c91a17380a5db7e2fa!]",

        # The repo token used for uploading data to Coveralls.io
        #        "ZEEK_COVERALLS_REPO_TOKEN": "ENCRYPTED[7ffd1e041f848f02b62f5abc7fda8a5a8a1561fbb2b46d88cefb67c74408ddeef6ea6f3b279c7953ca14ae9b4d050e2d]",
        "CCACHE_BASEDIR": "$CIRRUS_WORKING_DIR",
        "CCACHE_DIR": "/tmp/ccache",
        "CCACHE_COMPRESS": "1",

        # Ensure reasonable ccache upper limits to avoid spending too much time on pulling
        # and pushing the cache folder.  However, cache eviction with Cirrus CI is
        # currently random due to mtime not being preserved through the cache instruction:
        # https://github.com/cirruslabs/cirrus-ci-agent/issues/277
        "CCACHE_MAXSIZE": "1000M",
        "CCACHE_MAXFILES": "20000",

        # Size to use when manually pruning the cache below. This size should be roughly
        # `CCACHE_MAXSIZE - <build_size>`. This works around
        # https://github.com/cirruslabs/cirrus-ci-agent/issues/277.
        "ZEEK_CCACHE_PRUNE_SIZE": "700M",

        # Increase this to flush the ccache cache. Mainly useful until there's a solution
        # for the mtime pruning above.
        "ZEEK_CCACHE_EPOCH": "2",
    }

def macos_environment(config_opts):
    env = default_environment(config_opts)
    env.update({
        # TODO: why do we set these if Cirrus still forces us back to 8 CPUs?
        "ZEEK_CI_CPUS": 12,
        "ZEEK_CI_BTEST_JOBS": 12,
        # No permission to write to the default location of /zeek on macOS
        # TODO: verify this is still the case
        "CIRRUS_WORKING_DIR": "/tmp/zeek",
        "ZEEK_CI_CONFIGURE_FLAGS": configure_opt_macos(),
    })
    return env

def freebsd_environment(config_opts):
    env = default_environment(config_opts)
    env.update({
        # TODO: why do we set these here to different values instead of letting
        # the standard environment set them?
        "ZEEK_CI_CPUS": 8,
        "ZEEK_CI_BTEST_JOBS": 8,
    })
    return env

def default_instructions():
    return [
        # TODO: The cache instructions are missing "reupload_on_changes"
        script("sync_submodules", "git submodule update --recursive --init"),
        cache(
            name = "get_external_pcaps",
            folder = "testing/external/zeek-testing-traces",
            fingerprint_script = "echo zeek-testing-traces",
            populate_script = "./ci/init-external-repos.sh",
        ),
        cache(
            name = "ccache",
            folder = "/tmp/cache",
            fingerprint_script = "echo ccache-$ZEEK_CCACHE_EPOCH-$CIRRUS_TASK_NAME-$CIRRUS_OS",
        ),
        script("init_external_repos", "./ci/init-external-repos.sh"),
        script("pre_build", "./ci/pre-build.sh"),
        script("build", "./ci/build.sh"),
        script("test", "./ci/test.sh"),
        on_failure(artifacts(
            "upload_btest_tmp_dir",
            "testing/**/tmp.tar.gz",
        )),
        always(artifacts(
            name = "upload_btest_xml_results",
            path = "testing/**/btest-results.xml",
            type = "text/xml",
            format = "junit",
        )),
        always(artifacts(
            name = "upload_btest_html_results",
            path = "testing/**/btest-results.html",
            type = "text/html",
        )),
        always(script("cache_statistics", "ccache --show-stats")),
        # Evict some of the cached build artifacts not used in this build.
        always(script(
            "ccache_prune",
            "CCACHE_MAXSIZE=${ZEEK_CCACHE_PRUNE_SIZE} ccache -c",
        )),
    ]

def ci_template():
    return {
        # Default timeout is 60 minutes. Cirrus has a hard limit of 120 minutes for free
        # tasks, so may as well ask for full time.
        "timeout_in": "120m",
    }
