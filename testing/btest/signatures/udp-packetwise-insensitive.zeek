# @TEST-EXEC: zeek -b -r $TRACES/udp-signature-test.pcap %INPUT | sort >out
# @TEST-EXEC: btest-diff out

@load-sigs test.sig

@TEST-START-FILE test.sig
signature xxxx {
 ip-proto = udp
 payload /xXxX/i
 event "Found XXXX"
}

signature axxxx {
 ip-proto = udp
 payload /^xxxx/i
 event "Found ^XXXX"
}

signature sxxxx {
 ip-proto = udp
 payload /.*xxXx/i
 event "Found .*XXXX"
}

signature yyyy {
 ip-proto = udp
 payload /YYYY/i
 event "Found YYYY"
}

signature ayyyy {
 ip-proto = udp
 payload /^YYYY/i
 event "Found ^YYYY"
}

signature syyyy {
 ip-proto = udp
 payload /.*YYYY/i
 event "Found .*YYYY"
}

signature nope {
 ip-proto = udp
 payload /.*nope/i
 event "Found .*nope"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print "signature match", msg, data;
	}
