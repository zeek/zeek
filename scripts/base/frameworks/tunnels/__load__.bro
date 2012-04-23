@load ./main

const ports = { 5072/udp } &redef;
redef dpd_config += { [ANALYZER_AYIYA] = [$ports = ports] };
