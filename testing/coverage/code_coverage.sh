#!/usr/bin/env bash
#
# On a Zeek build configured with --enable-coverage, this script
# produces a code coverage report after Zeek has been invoked. The
# intended application of this script is after the btest testsuite has
# run. This combination (btests first, coverage computation afterward)
# happens automatically when running "make" in the testing directory.
#
# This depends on gcov, which should come with your gcc.
#
# AUTOMATES CODE COVERAGE TESTING
#	1. Run test suite
# 	2. Check for .gcda files existing.
#	3a. Run gcov (-p to preserve path)
#       3b. Prune .gcov files for objects outside of the Zeek tree
#	4a. Analyze .gcov files generated and create summary file
#	4b. Send .gcov files to appropriate path
#
CURR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # Location of script
BASE="$(cd "$CURR" && cd ../../ && pwd)"
TMP="${CURR}/tmp.$$"
mkdir -p $TMP

# DEFINE CLEANUP PROCESS
function finish {
    rm -rf $TMP
}
trap finish EXIT

# DEFINE CRUCIAL FUNCTIONS FOR COVERAGE CHECKING
function check_file_coverage {
    GCOVDIR="$1"

    for i in $GCOVDIR/*.gcov; do
        # Effective # of lines: starts with a number (# of runs in line) or ##### (line never run)
        TOTAL=$(cut -d: -f 1 "$i" | sed 's/ //g' | grep -v "^[[:alpha:]]" | grep -v "-" | wc -l)

        # Count number of lines never run
        UNRUN=$(grep "#####" "$i" | wc -l)

        # Lines in code are either run or unrun
        RUN=$(($TOTAL - $UNRUN))

        # Avoid division-by-zero problems:
        PERCENTAGE=0.000
        [ $RUN -gt 0 ] && PERCENTAGE=$(bc <<<"scale=3; 100*$RUN/$TOTAL")

        # Find correlation between % of lines run vs. "Runs"
        echo -e "$PERCENTAGE\t$RUN\t$TOTAL\t$(grep "0:Runs" "$i" | sed 's/.*://')\t$i"
    done
}

function check_group_coverage {
    DATA="$1"       # FILE CONTAINING COVERAGE DATA
    SRC_FOLDER="$2" # WHERE ZEEK WAS COMPILED
    OUTPUT="$3"

    # Prints all the relevant directories
    DIRS=$(for i in $(cut -f 5 "$DATA"); do basename "$i" | sed 's/#[^#]*$//'; done |
        sort | uniq | sed 's/^.*'"${SRC_FOLDER}"'//' | grep "^#s\+")
    # "Generalize" folders unless it's from analyzers
    DIRS=$(for i in $DIRS; do
        if !(echo "$i" | grep "src#analyzer"); then
            echo "$i" | cut -d "#" -f 1,2,3
        fi
    done | sort | uniq)

    for i in $DIRS; do
        # For elements in #src, we only care about the files directly in the directory.
        if [[ "$i" = "#src" ]]; then
            RUN=$(echo $(grep "$i#[^#]\+$" $DATA | grep "$SRC_FOLDER$i\|build$i" | cut -f 2) | tr " " "+" | bc)
            TOTAL=$(echo $(grep "$i#[^#]\+$" $DATA | grep "$SRC_FOLDER$i\|build$i" | cut -f 3) | tr " " "+" | bc)
        else
            RUN=$(echo $(grep "$i" $DATA | cut -f 2) | tr " " "+" | bc)
            TOTAL=$(echo $(grep "$i" $DATA | cut -f 3) | tr " " "+" | bc)
        fi

        PERCENTAGE=$(echo "scale=3;100*$RUN/$TOTAL" | bc | tr "\n" " ")
        printf "%-50s\t%12s\t%6s %%\n" "$i" "$RUN/$TOTAL" $PERCENTAGE |
            sed 's|#|/|g' >>$OUTPUT
    done
}

# 1. Run test suite
# SHOULD HAVE ALREADY BEEN RUN BEFORE THIS SCRIPT (BASED ON MAKEFILE TARGETS)

# 2. Check for .gcno and .gcda file presence
echo -n "Checking for coverage files... "
for pat in gcda gcno; do
    if [ -z "$(find "$BASE" -name "*.$pat" 2>/dev/null)" ]; then
        echo "no .$pat files, nothing to do"
        exit 0
    fi
done
echo "ok"

# 3a. Run gcov (-p to preserve path) and move into tmp directory
# ... if system does not have gcov installed, exit with message.
echo -n "Creating coverage files... "
if which gcov >/dev/null 2>&1; then
    (cd "$TMP" && find "$BASE" -name "*.o" -exec gcov -p {} \; >/dev/null 2>&1)
    NUM_GCOVS=$(find "$TMP" -name *.gcov | wc -l)
    if [ $NUM_GCOVS -eq 0 ]; then
        echo "no gcov files produced, aborting"
        exit 1
    fi

    # Account for '^' that occurs in macOS due to LLVM
    # This character seems to be equivalent to ".." (up 1 dir)
    for file in $(ls $TMP/*.gcov | grep '\^'); do
        mv $file "$(sed 's/#[^#]*#\^//g' <<<"$file")"
    done

    echo "ok, $NUM_GCOVS coverage files"
else
    echo "gcov is not installed on system, aborting"
    exit 1
fi

# 3b. Prune gcov files that fall outside of the Zeek tree:
# Look for files containing gcov's slash substitution character "#"
# and remove any that don't contain the Zeek path root.
echo -n "Pruning out-of-tree coverage files... "
PREFIX=$(echo "$BASE" | sed 's|/|#|g')
for i in "$TMP"/*#*.gcov; do
    if ! [[ "$i" = *$PREFIX* ]]; then
        rm -f $i
    fi
done
NUM_GCOVS=$(ls "$TMP"/*.gcov | wc -l)
echo "ok, $NUM_GCOVS coverage files remain"

# 4a. Analyze .gcov files generated and create summary file
echo -n "Creating summary file... "
DATA="${TMP}/data.txt"
SUMMARY="$CURR/coverage.log"
check_file_coverage "$TMP" >"$DATA"
check_group_coverage "$DATA" ${BASE##*/} $SUMMARY
echo "ok"

# 4b. Send .gcov files to appropriate path
echo -n "Sending coverage files to respective directories... "
for i in "$TMP"/*#*.gcov; do
    mv $i $(echo $(basename $i) | sed 's/#/\//g')
done
echo "ok"
