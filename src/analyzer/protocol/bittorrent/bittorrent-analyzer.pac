# This code contributed by Nadi Sarrar.

connection BitTorrent_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = BitTorrent_Flow(true);
	downflow = BitTorrent_Flow(false);
};

flow BitTorrent_Flow(is_orig: bool) {
	flowunit = BitTorrent_PDU withcontext (connection, this);

	%member{
		bool handshake_ok;
		//uint64 _next_message_offset;
	%}

	%init{
		handshake_ok = false;
		//_next_message_offset = 0;
	%}

	#function next_message_offset(): uint64
	#	%{
	#	return &_next_message_offset;
	#	%}

	#function increment_next_message_offset(go: bool, len: uint32): bool
	#	%{
	#	if ( go )
	#		_next_message_offset += len;
	#	return true;
	#	%}

	function is_handshake_delivered(): bool
		%{
		return handshake_ok;
		%}

	function validate_handshake(pstrlen: uint8, pstr: const_bytestring): bool
		%{
		if ( pstrlen != 19 ||
		     memcmp("BitTorrent protocol", pstr.begin(), 19) )
			{
			throw Exception("invalid handshake");
			}

		return true;
		%}

	function validate_message_length(len: uint32): bool
		%{
		if ( len > MSGLEN_LIMIT )
			throw Exception(zeek::util::fmt("message length prefix exceeds limit: %u > %u",
					len, MSGLEN_LIMIT));
		return true;
		%}

	function deliver_handshake(reserved: const_bytestring,
					info_hash: const_bytestring,
					peer_id: const_bytestring): bool
		%{
		handshake_ok = true;
		if ( ::bittorrent_peer_handshake )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_handshake(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				to_stringval(reserved),
				to_stringval(info_hash),
				to_stringval(peer_id));
			}

		connection()->zeek_analyzer()->AnalyzerConfirmation();

		return true;
		%}

	function deliver_keep_alive(): bool
		%{
		if ( ::bittorrent_peer_keep_alive )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_keep_alive(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_choke(): bool
		%{
		if ( ::bittorrent_peer_choke )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_choke(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_unchoke(): bool
		%{
		if ( ::bittorrent_peer_unchoke )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_unchoke(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_interested(): bool
		%{
		if ( ::bittorrent_peer_interested )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_interested(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_not_interested(): bool
		%{
		if ( ::bittorrent_peer_not_interested )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_not_interested(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_have(piece_index: uint32): bool
		%{
		if ( ::bittorrent_peer_have )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_have(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				piece_index);
			}

		return true;
		%}

	function deliver_bitfield(bitfield: const_bytestring): bool
		%{
		if ( ::bittorrent_peer_bitfield )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_bitfield(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				to_stringval(bitfield));
			}

		return true;
		%}

	function deliver_request(index: uint32, begin: uint32,
					length: uint32): bool
		%{
		if ( ::bittorrent_peer_request )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_request(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				index, begin, length);
			}

		return true;
		%}

	function deliver_piece(index: uint32, begin: uint32,
				piece_length: uint32): bool
		%{
		if ( ::bittorrent_peer_piece )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_piece(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				index, begin, piece_length);
			}

		return true;
		%}

	function deliver_cancel(index: uint32, begin: uint32,
				length: uint32): bool
		%{
		if ( ::bittorrent_peer_cancel )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_cancel(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				index, begin, length);
			}

		return true;
		%}

	function deliver_port(listen_port: uint16): bool
		%{
		if ( ::bittorrent_peer_port )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_port(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				zeek::val_mgr->Port(listen_port, TRANSPORT_TCP));
			}

		return true;
		%}

	function deliver_unknown(id: uint8, data: const_bytestring): bool
		%{
		if ( ::bittorrent_peer_unknown )
			{
			zeek::BifEvent::enqueue_bittorrent_peer_unknown(
				connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig(),
				id,
				to_stringval(data));
			}

		return true;
		%}
};
