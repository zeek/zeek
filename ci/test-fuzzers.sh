#! /usr/bin/env bash

result=0

echo "Testing fuzzers against their seed corpus"
echo "-----------------------------------------"

cd build || result=1
. ./zeek-path-dev.sh

fuzzers=$(find ./src/fuzzers -name 'zeek-*-fuzzer')

for fuzzer_path in ${fuzzers}; do
    fuzzer_exe=$(basename ${fuzzer_path})
    fuzzer_name=$(echo ${fuzzer_exe} | sed 's/zeek-\(.*\)-fuzzer/\1/g')
    corpus="../src/fuzzers/corpora/${fuzzer_name}-corpus.zip"

    if [[ -e ${corpus} ]]; then
        echo "Fuzzer: ${fuzzer_exe} ${corpus}"
        (rm -rf corpus && mkdir corpus) || result=1
        (cd corpus && unzip ../${corpus} >/dev/null) || result=1
        ${fuzzer_path} corpus/* >${fuzzer_exe}.out 2>${fuzzer_exe}.err

        if [[ $? -eq 0 ]]; then
            tail -n 1 ${fuzzer_exe}.out
        else
            result=1
            cat ${fuzzer_exe}.out
            echo "    FAILED"
            cat ${fuzzer_exe}.err
        fi
    else
        echo "Skipping Fuzzer (no corpus): ${fuzzer_exe}"
    fi

    echo "-----------------------------------------"
done

exit ${result}
