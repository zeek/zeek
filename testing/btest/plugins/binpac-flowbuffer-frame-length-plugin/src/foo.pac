%include binpac.pac
%include zeek.pac

%extern{
	#include "foo.bif.h"
%}

analyzer FOO withcontext {
	connection: FOO_Conn;
	flow:       FOO_Flow;
};

# Our connection consists of two flows, one in each direction.
connection FOO_Conn(bro_analyzer: ZeekAnalyzer) {
	upflow   = FOO_Flow(true);
	downflow = FOO_Flow(false);
};

type HDR = record {
    version:    uint8;
    reserved:   uint8;
    len:        uint16;
} &byteorder=bigendian;

type FOO_PDU(is_orig: bool) = record {
    hdr:        HDR;
    plen:       uint8;
    ptype:      uint8;
    something:  bytestring &restofdata;
} &byteorder=bigendian, &length=hdr.len;

# Now we define the flow:
flow FOO_Flow(is_orig: bool) {

	flowunit = FOO_PDU(is_orig) withcontext(connection, this);
	# datagram = FOO_PDU(is_orig) withcontext(connection, this);

};

refine flow FOO_Flow += {
    function proc_foo_message(msg: FOO_PDU): bool
        %{
        // printf("FOO %d %d\n", msg->hdr()->len(), msg->hdr_len());
        connection()->bro_analyzer()->ProtocolConfirmation();
        zeek::BifEvent::Foo::enqueue_foo_message(
                        connection()->bro_analyzer(),
                        connection()->bro_analyzer()->Conn(),
                        is_orig(),
                        msg->hdr()->len(),
                        msg->plen(),
                        msg->ptype());
        return true;
        %}

};

refine typeattr FOO_PDU += &let {
    proc: bool = $context.flow.proc_foo_message(this);
};
