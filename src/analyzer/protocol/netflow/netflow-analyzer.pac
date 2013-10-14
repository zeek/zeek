# Code written by Bernhard Ager (2007).

analyzer NetFlow withcontext {
	analyzer:	NetFlow_Analyzer;
	flow:		NetFlow_Flow;
}

analyzer NetFlow_Analyzer {
	downflow = NetFlow_Flow;
	upflow = NetFlow_Flow;
};

flow NetFlow_Flow {
	datagram = NetFlowPacket withcontext(connection, this);

	%member{
		RecordType* nf_v5_header_type;
		RecordType* nf_v5_record_type;
		RecordType* nfheader_id_type;
		char* identifier;
		uint32 exporter_ip;
		uint32 uptime;
		double export_time;
		bro_uint_t pdu_id;
	%}

	%init{
		nf_v5_header_type =
			internal_type("nf_v5_header")->AsRecordType();
		nf_v5_record_type =
			internal_type("nf_v5_record")->AsRecordType();
		nfheader_id_type =
			internal_type("nfheader_id")->AsRecordType();
		identifier = NULL;
		exporter_ip = 0;
		uptime = 0;
		export_time = 0;
		pdu_id = 0;
	%}

	# %cleanup does not only put the cleanup code into the destructor,
	# but also at the end of the catch clause in NewData().  This is
	# different from the documentation at
	# http://www.bro.org/wiki/index.php/BinPAC_Userguide#.25cleanup.7B....25.7D
	#
	# Unfortunately this means that we cannot clean up the identifier
	# string.  Note that IOSource destructors seemingly are never
	# called anyway.
	#
	#    %cleanup{
	#	delete[] identifier;
	#    %}

	function set_exporter_ip(exporter_ip: uint32): bool
		%{
		this->exporter_ip = exporter_ip;
		return true;
		%}

	function set_identifier(idf: const_charptr): bool
		%{
		if ( identifier )
			delete[] identifier;
		identifier = new char[strlen(idf) + 1];
		strcpy(identifier, idf);
		return true;
		%}

	function deliver_v5_header(count: uint16, sysuptime: uint32,
				unix_secs: uint32, unix_nsecs: uint32,
				flow_seq: uint32, eng_type: uint8,
				eng_id: uint8, sample_int: uint16): bool
		%{
		uptime = sysuptime;
		export_time = unix_secs + unix_nsecs / 1e9;
		++pdu_id;

		if ( ! ::netflow_v5_header )
			return false;

		RecordVal* nfheader = new RecordVal(nfheader_id_type);
		nfheader->Assign(0, new StringVal(identifier));
		nfheader->Assign(1, new Val(pdu_id, TYPE_COUNT));

		RecordVal* v5header = new RecordVal(nf_v5_header_type);
		v5header->Assign(0, nfheader);
		v5header->Assign(1, new Val(count, TYPE_COUNT));
		v5header->Assign(2, new IntervalVal(sysuptime, Milliseconds));
		v5header->Assign(3, new Val(export_time, TYPE_TIME));
		v5header->Assign(4, new Val(flow_seq, TYPE_COUNT));
		v5header->Assign(5, new Val(eng_type, TYPE_COUNT));
		v5header->Assign(6, new Val(eng_id, TYPE_COUNT));
		v5header->Assign(7, new Val(sample_int, TYPE_COUNT));
		v5header->Assign(8, new AddrVal(exporter_ip));

		val_list* vl = new val_list;
		vl->append(v5header);
		mgr.QueueEvent(netflow_v5_header, vl);

		return true;
		%}

	function deliver_v5_record(srcaddr: uint32, dstaddr: uint32,
				nexthop: uint32, input: uint16, output: uint16,
				dPkts: uint32, dOctets: uint32,
				first: uint32, last: uint32,
				srcport: uint16, dstport: uint16,
				tcp_flags: uint8, prot: uint8, tos: uint8,
				src_as: uint16, dst_as: uint16,
				src_mask: uint8, dst_mask: uint8): bool
		%{
		if ( ! ::netflow_v5_record )
			return false;

		TransportProto proto = TRANSPORT_UNKNOWN;
		switch ( prot ) {
		case 1: proto = TRANSPORT_ICMP; break;
		case 6: proto = TRANSPORT_TCP; break;
		case 17: proto = TRANSPORT_UDP; break;
		}

		RecordVal* connid = new RecordVal(conn_id);
		connid->Assign(0, new AddrVal(htonl(srcaddr)));
		connid->Assign(1, new PortVal(srcport, proto));
		connid->Assign(2, new AddrVal(htonl(dstaddr)));
		connid->Assign(3, new PortVal(dstport, proto));

		RecordVal* nfheader = new RecordVal(nfheader_id_type);
		nfheader->Assign(0, new StringVal(identifier));
		nfheader->Assign(1, new Val(pdu_id, TYPE_COUNT));

		RecordVal* v5record = new RecordVal(nf_v5_record_type);
		v5record->Assign(0, nfheader);
		v5record->Assign(1, connid);
		v5record->Assign(2, new AddrVal(htonl(nexthop)));
		v5record->Assign(3, new Val(input, TYPE_COUNT));
		v5record->Assign(4, new Val(output, TYPE_COUNT));
		v5record->Assign(5, new Val(dPkts, TYPE_COUNT));
		v5record->Assign(6, new Val(dOctets, TYPE_COUNT));

		// Overflows are handled correctly by using 32 bit
		// unsigned integer arithmetic.
		double c_first = export_time - (uptime - first) * Milliseconds;
		double c_last = export_time - (uptime - last) * Milliseconds;
		v5record->Assign(7, new Val(c_first, TYPE_TIME));
		v5record->Assign(8, new Val(c_last, TYPE_TIME));

		v5record->Assign(9,
			new Val((tcp_flags & TH_FIN) != 0, TYPE_BOOL));
		v5record->Assign(10,
			new Val((tcp_flags & TH_SYN) != 0, TYPE_BOOL));
		v5record->Assign(11,
			new Val((tcp_flags & TH_RST) != 0, TYPE_BOOL));
		v5record->Assign(12,
			new Val((tcp_flags & TH_PUSH) != 0, TYPE_BOOL));
		v5record->Assign(13,
			new Val((tcp_flags & TH_ACK) != 0, TYPE_BOOL));
		v5record->Assign(14,
			new Val((tcp_flags & TH_URG) != 0, TYPE_BOOL));

		v5record->Assign(15, new Val(prot, TYPE_COUNT));
		v5record->Assign(16, new Val(tos, TYPE_COUNT));
		v5record->Assign(17, new Val(src_as, TYPE_COUNT));
		v5record->Assign(18, new Val(dst_as, TYPE_COUNT));
		v5record->Assign(19, new Val(src_mask, TYPE_COUNT));
		v5record->Assign(20, new Val(dst_mask, TYPE_COUNT));

		val_list* vl = new val_list;
		vl->append(v5record);
		mgr.QueueEvent(netflow_v5_record, vl);

		return true;
		%}
	};
