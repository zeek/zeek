%extern{
#include "zeek/binpac_zeek.h"
%}

extern type ZeekAnalyzer;
extern type ZeekPacketAnalyzer;
extern type ZeekVal;
extern type ZeekPortVal;
extern type ZeekStringVal;

function network_time(): double;
