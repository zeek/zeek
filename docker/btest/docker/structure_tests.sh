# @TEST-REQUIRES: docker inspect ${TEST_TAG:-zeek:latest}
# @TEST-EXEC: bash -euxo pipefail %INPUT >output
# @TEST-EXEC: btest-diff output

TEST_TAG=${TEST_TAG:-zeek:latest}

# Check that `zeek` can be run.
docker run --rm "${TEST_TAG}" zeek -v | sed 's/\(zeek version\) .*/\1 xxx/'

# ...and load and execute some basic scripts, too.
docker run --rm "${TEST_TAG}" zeek -e 'print fmt("zeek version %s", zeek_version())' | sed 's/\(zeek version\) .*/\1 xxx/'

# Check that this is a release build.
docker run --rm "${TEST_TAG}" zeek-config --build_type | grep -q 'release'

# Check that `btest` can be run.
docker run --rm "${TEST_TAG}" btest --version | sed 's/^[0-9].*/XXX/g'

# Check that the zkg config looks valid.
docker run --rm "${TEST_TAG}" zkg config

# Check that a plugin can be installed. We pick any plugin with minimal deps here.
docker run --rm "${TEST_TAG}" zkg install --force sethhall/domain-tld |
    sed 's/"\.*$/"/' |
    sed 's/(.*)/(XXX)/'

# Check that the Broker Python module loads
docker run --rm "${TEST_TAG}" python3 -c "import broker"
