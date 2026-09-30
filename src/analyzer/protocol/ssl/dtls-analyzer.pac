%extern{
#include <cinttypes>

using DTLS_Reassembler = zeek::analyzer::dtls::DTLS_Reassembler;
%}

refine connection SSL_Conn += {

	%member{

		struct message_info {
			uint16 message_handshake_sequence = 0; // the handshake sequence number of this handshake (to identify)
			uint32 message_length = 0; // data length of this handshake (expected size)
			std::unique_ptr<DTLS_Reassembler> reassembler;
		} server, client;
	%}

	%cleanup{
		// Reassembler lifetime bound to analyzer.
		server.reassembler.reset();
		client.reassembler.reset();
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

		// is the data buffer as long as announced?
		if ( ${rec.data}.length() != flength )
			{
			zeek_analyzer()->AnalyzerViolation("DTLS handshake record length does not match packet length");
			return true;
			}

		// do not allow fragments beyond the announce message length
		if ( foffset + flength > length )
			{
			zeek_analyzer()->AnalyzerViolation("DTLS handshake fragment trying to write past end of buffer");
			return true;
			}

		// (Re-)Initialize fragment reassembly if needed.
		if ( i->message_handshake_sequence != ${rec.message_seq} || i->message_length != length || ! i->reassembler )
			{
			i->reassembler = std::make_unique<DTLS_Reassembler>(zeek_analyzer());
			i->message_handshake_sequence = ${rec.message_seq};
			i->message_length = length;
			}

		// Handle the fragment through the reassembler.
		i->reassembler->NewBlock(zeek::run_state::network_time, foffset, flength, ${rec.data}.data());

		// Completed?
		if ( i->reassembler->TotalSize() >= i->message_length )
			{
			auto buffer = std::move(*(i->reassembler)).TakeBuffer();
			if ( buffer.size() != static_cast<size_t>(length) )  // just some sanity check
				zeek_analyzer()->Weird("DTLS_weird_reassembled_buffer_length");

			zeek_analyzer()->SendHandshake(${pdu.raw_tls_version}, ${rec.msg_type}, length, buffer.data(), buffer.data() + buffer.size(), ${pdu.is_orig});

			i->reassembler.reset();
			return true;
			}

		if ( i->reassembler->NumBlocks() > 30 )
			{
			zeek_analyzer()->LimitReachedWeird("DTLS_excessive_fragments", i->reassembler->NumBlocks());
			zeek_analyzer()->AnalyzerViolation("DTLS Message fragmented over more than 30 pieces. Cannot reassemble.");

			i->reassembler.reset();
			return true;
			}
		else if ( i->reassembler->Overlaps() > 30 )
			{
			zeek_analyzer()->LimitReachedWeird("DTLS_excessive_fragment_overlaps", i->reassembler->Overlaps());
			zeek_analyzer()->AnalyzerViolation("DTLS Message fragmented with more than 30 overlapping pieces. Cannot reassemble.");

			i->reassembler.reset();
			return true;
			}

		return true;
		%}

		function proc_unified_record(is_orig: bool, ur: UnifiedRecord) : bool
			%{
			// we don't have a CCS packet anymore - so let's just assume the connection is established once we have seen a packet from each direction.
			if ( is_orig )
				client_state_ = STATE_ENCRYPTED;
			else
				server_state_ = STATE_ENCRYPTED;

			if ( client_state_ == STATE_ENCRYPTED && server_state_ == STATE_ENCRYPTED && established_ == false )
				{
				established_ = true;
				if ( ssl_established )
					zeek::BifEvent::enqueue_ssl_established(zeek_analyzer(), zeek_analyzer()->Conn());
				}

			if ( ssl_encrypted_data )
				{
				// In case a CID is given, swallow is not quite the correct length, because we are not parsing the entire header. This is not entirely
				// trivial to work around, and the workaround won't work in all cases - and it might also not matter.
				// We also have more potentially interesting information (the sequence number) - which we don't currently give to scriptland.
				zeek::BifEvent::enqueue_ssl_encrypted_data(zeek_analyzer(),
					zeek_analyzer()->Conn(), is_orig ^ zeek_analyzer()->GetFlipped(), DTLSv13, APPLICATION_DATA, ur->swallow().length());
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

refine typeattr UnifiedRecord += &let {
	proc: bool = $context.connection.proc_unified_record(is_orig, this);
};
