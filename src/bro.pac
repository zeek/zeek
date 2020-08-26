%extern{
#warning "bro.pac is deprecated and will be removed in v4.1. Use zeek.pac instead."
#include "binpac_bro.h"
%}

extern type BroAnalyzer;
extern type BroVal;
extern type BroPortVal;
extern type BroStringVal;

function network_time(): double;
