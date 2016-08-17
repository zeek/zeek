%extern{
#include "binpac_bro.h"
%}

extern type BroAnalyzer;
extern type BroVal;
extern type BroPortVal;
extern type BroStringVal;

function network_time(): double;
function utf16_bytestring_to_utf8_val(conn: Connection, utf16: bytestring): StringVal;
