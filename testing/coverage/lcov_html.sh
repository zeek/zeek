#!/usr/bin/env bash
#
# On a Zeek build configured with --enable-coverage, this script
# produces a code coverage report in HTML format after Zeek has been invoked. The
# intended application of this script is after the btest testsuite has run.

# This depends on lcov to run.

function die {
    echo "$@"
    exit 1
}
function finish {
    rm -rf "$TMP"
}
function verify_run {
    if bash -c "$1" >/dev/null 2>&1; then
        echo ${2:-"ok"}
    else
        die ${3:-"error, abort"}
    fi
}
trap finish EXIT

HTML_REPORT=1
COVERALLS_REPO_TOKEN=""
COVERAGE_HTML_DIR=""

function usage {
    usage="\
Usage: $0 <options>

  Generate coverage data for the Zeek code. This uses data generated during btest,
  so those should be run prior to calling this script. By default, this script
  generates an HTML report in the coverage-html directory in the root of the Zeek
  repo.

  Options:
    --help             Display this output.
    --html DIR         This is the default mode, but this argument can be passed
                       to make it explicit. It also can be used to pass an optional
                       destination directory for the HTML output.
    --coveralls TOKEN  Report coverage data to Coveralls.io using the specified
                       repo token. Enabling this option disables the HTML report.
                       This option requires the coveralls-lcov Ruby gem to be
                       installed.
"

    echo "${usage}"
    exit 1
}

while (("$#")); do
    case "$1" in
        --html)
            HTML_REPORT=1
            if [ ${#2} -eq 0 ]; then
                COVERAGE_HTML_DIR="coverage-html"
                shift 1
            else
                COVERAGE_HTML_DIR=$2
                shift 2
            fi
            ;;
        --coveralls)
            if [ ${#2} -eq 0 ]; then
                echo "ERROR: Coveralls repo token must be passed with --coveralls argument."
                echo
                usage
            fi

            HTML_REPORT=0
            COVERALLS_REPO_TOKEN=$2
            shift 2
            ;;
        --help)
            usage
            shift 1
            ;;
        *)
            COVERAGE_HTML_DIR="${1:-"coverage-html"}"
            shift 1
            ;;
    esac
done

TMP=".tmp.$$"
COVERAGE_FILE="./$TMP/coverage.info"

if [ -z "${COVERAGE_HTML_DIR}" ]; then
    COVERAGE_HTML_DIR="coverage-html"
fi

# Files and directories that will be removed from the counts in step 5. Directories
# need to be surrounded by escaped wildcards.
REMOVE_TARGETS="*.yy *.ll *.y *.l \*/bro.dir/\* *.bif \*/zeek.dir/\* \*/src/3rdparty/\* \*/src/zeek/3rdparty/\* \*/auxil/\* "

# 1. Move to base dir, create tmp dir
cd ../../
mkdir "$TMP"

# 2. Check for .gcno and .gcda file presence
echo -n "Checking for coverage files... "
for pat in gcda gcno; do
    if [ -z "$(find . -name "*.$pat" 2>/dev/null)" ]; then
        echo "no .$pat files, nothing to do"
        exit 0
    fi
done
echo "ok"

# 3. If lcov does not exist, abort process.
echo -n "Checking for lcov... "
verify_run "which lcov" \
    "lcov installed on system, continue" \
    "lcov not installed, abort"

# 4. Create a "tracefile" through lcov, which is necessary to create output later on.
echo -n "Creating tracefile for output generation... "
verify_run "lcov --no-external --capture --directory . --output-file $COVERAGE_FILE"

# 5. Remove a number of 3rdparty and "extra" files that shouldn't be included in the
# Zeek coverage numbers.
for TARGET in $REMOVE_TARGETS; do
    echo -n "Getting rid of $TARGET files from tracefile... "
    verify_run "lcov --remove $COVERAGE_FILE $TARGET --output-file $COVERAGE_FILE"
done

# 6. Create HTML files or Coveralls report
if [ $HTML_REPORT -eq 1 ]; then
    echo -n "Creating HTML files... "
    verify_run "genhtml -o $COVERAGE_HTML_DIR $COVERAGE_FILE"
else
    # The data we send to coveralls has a lot of duplicate files in it because of the
    # zeek symlink in the src directory. Run a script that cleans that up.
    echo -n "Cleaning coverage data for Coveralls..."
    COVERAGE_FILE_CLEAN="${COVERAGE_FILE}.clean"
    verify_run "testing/coverage/coverage_cleanup.py ${COVERAGE_FILE} > ${COVERAGE_FILE_CLEAN} 2>&1"

    echo -n "Reporting to Coveralls..."
    coveralls_cmd="coveralls-lcov -t ${COVERALLS_REPO_TOKEN}"

    # If we're being called by Cirrus, add some additional information to the output.
    if [ -n "${CIRRUS_BUILD_ID}" ]; then
        coveralls_cmd="${coveralls_cmd} --service-name=cirrus --service-job-id=${CIRRUS_BUILD_ID}"
    else
        coveralls_cmd="${coveralls_cmd} --service-name=local"
    fi

    coveralls_cmd="${coveralls_cmd} ${COVERAGE_FILE_CLEAN}"

    verify_run "${coveralls_cmd}"
fi
