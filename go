. ~/src/zeek/build/zeek-path-dev.sh
export ASAN_OPTIONS=detect_odr_violation=0,detect_leaks=0

fz=$1
zeek_fuzz_analyer_${fz} ./${fz}_corpus/ -workers=4 -jobs=140 -max_total_time=300 -rss_limit_mb=5000 -malloc_limit_mb=50 -timeout=5
