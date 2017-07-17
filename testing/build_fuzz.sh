#apt-get -y install build-essential git bison flex gawk cmake swig libssl-dev libgeoip-dev libpcap-dev python-dev libcurl4-openssl-dev wget libncurses5-dev ca-certificates zlib1g-dev --no-install-recommends

git clone https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer
./fuzzer/build.sh

export FUZZ=1

CC=clang CXX=clang++ \
CFLAGS="-fsanitize-coverage=trace-pc-guard -fsanitize=address" \
CXXFLAGS="-fsanitize-coverage=trace-pc-guard -fsanitize=address" \
./configure --enable-debug
ASAN_OPTIONS=detect_leaks=0 make -j 3
