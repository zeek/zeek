
refine connection SSL_Conn += {

	%member{

		struct message_info {
			uint64 message_first_sequence; // the minumum dtls sequence number for this handshake fragment
			bool first_sequence_seen; // did we actually see the fragment with the smallest number
			uint64 message_last_sequence; // the maximum dtls sequence number for this handshake fragment
			uint16 message_handshake_sequence; // the handshake sequence number of this handshake (to identify)
			uint32 message_length; // data length of this handshake (data in buffer)
			uint32 message_sequence_seen; // a bitfield that shows which sequence numbers we already saw, offset from first_seq.
			u_char* buffer;
		} server, client;
	%}

	%init{
		memset(&server, 0, sizeof(server));
		memset(&client, 0, sizeof(client));
	%}

	%cleanup{
		delete [] server.buffer;
		delete [] client.buffer;
	%}

	function proc_dtls(pdu: SSLRecord, sequence: uint64): bool
		%{
		//fprintf(stderr, "Type: %d, sequence number: %d, epoch: %d\n", ${pdu.content_type}, sequence, ${pdu.epoch});

		return true;
		%}

	function proc_handshake(pdu: SSLRecord, rec: Handshake): bool
		%{
		uint32 foffset = to_int()(${rec.fragment_offset});
		int64  flength = to_int()(${rec.fragment_length});
		int64  length = to_int()(${rec.length});
		uint64 sequence_number = to_int()(${pdu.sequence_number});
		//fprintf(stderr, "Handshake type: %d, length: %u, seq: %u, foffset: %u, flength: %u\n", ${rec.msg_type}, to_int()(${rec.length}), ${rec.message_seq}, to_int()(${rec.fragment_offset}), to_int()(${rec.fragment_length}));

		if ( foffset == 0 && length == flength )
			{
			//fprintf(stderr, "Complete fragment, forwarding...\n");
			zeek_analyzer()->SendHandshake(${pdu.raw_tls_version}, ${rec.msg_type}, length, ${rec.data}.begin(), ${rec.data}.end(), ${pdu.is_orig});
			return true;
			}

		// if we fall through here, the message has to be reassembled. Let's first get the right info record...
		message_info* i;
		if ( ${pdu.is_orig} )
			i = &client;
		else
			i = &server;

		if ( length > MAX_DTLS_HANDSHAKE_RECORD )
			{
			zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("DTLS record length %" PRId64 " larger than allowed maximum.", length));
			return true;
			}

		if ( i->message_handshake_sequence != ${rec.message_seq} || i->message_length != length || i->buffer == 0 )
			{
			// cannot resume reassembling. Let's abandon the current data and try anew...
			delete [] i->buffer;
			memset(i, 0, sizeof(message_info));
			i->message_handshake_sequence = ${rec.message_seq};
			i->message_length = length;
			i->buffer = new u_char[length];
			// does not have to be the first sequence number - we cannot figure that out at this point. If it is not,
			// we will fix that later...
			i->message_first_sequence = sequence_number;
			}

		// if we arrive here, we are actually ready to resume.
		if ( i->message_first_sequence > sequence_number )
			{
			if ( i->first_sequence_seen )
				{
				zeek_analyzer()->AnalyzerViolation("Saw second and different first message fragment for handshake.");
				return true;
				}
			// first sequence number was incorrect, let's fix that.
			uint64 diff = i->message_first_sequence - sequence_number;
			i->message_sequence_seen = i->message_sequence_seen << diff;
			i->message_first_sequence = sequence_number;
			}

		// if we have offset 0, we know the smallest number...
		if ( foffset == 0 )
			i->first_sequence_seen = true;

		// check if we already saw the message
		if ( ( i->message_sequence_seen & ( 1 << (sequence_number - i->message_first_sequence) ) ) != 0 )
			return true; // do not handle same message fragment twice

		// copy data from fragment to buffer
		if ( ${rec.data}.length() != flength )
			{
			zeek_analyzer()->AnalyzerViolation("DTLS handshake record length does not match packet length");
			return true;
			}

		if ( foffset + flength > length )
			{
			zeek_analyzer()->AnalyzerViolation("DTLS handshake fragment trying to write past end of buffer");
			return true;
			}

		// store that we handled fragment
		i->message_sequence_seen |= 1 << (sequence_number - i->message_first_sequence);
		memcpy(i->buffer + foffset, ${rec.data}.data(), ${rec.data}.length());

		//fprintf(stderr, "Copied to buffer offset %u length %u\n", foffset, ${rec.data}.length());

		// store last fragment information if this is the last fragment...

		// check if we saw all fragments so far. If yes, forward...
		if ( foffset + flength == length )
			i->message_last_sequence = sequence_number;

		if ( i->message_last_sequence != 0 && i->first_sequence_seen )
			{
			uint64 total_length = i->message_last_sequence - i->message_first_sequence;
			if ( total_length > 30 )
				{
				zeek_analyzer()->AnalyzerViolation("DTLS Message fragmented over more than 30 pieces. Cannot reassemble.");
				return true;
				}

			if ( ( ~(i->message_sequence_seen) & ( ( 1<<(total_length+1) ) -1 ) ) == 0 )
				{
				//fprintf(stderr, "ALl fragments here. Total length %u\n", length);
				zeek_analyzer()->SendHandshake(${pdu.raw_tls_version}, ${rec.msg_type}, length, i->buffer, i->buffer + length, ${pdu.is_orig});
				}
			}


		return true;
		%}
};

refine typeattr SSLRecord += &let {
	proc: bool = $context.connection.proc_dtls(this, to_int()(sequence_number));
};

refine typeattr Handshake += &let {
	proc: bool = $context.connection.proc_handshake(rec, this);
};
