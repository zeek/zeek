# This code contributed by Nadi Sarrar.

connection BitTorrent_Conn(bro_analyzer: BroAnalyzer) {
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
			connection()->bro_analyzer()->Weird(fmt("BitTorrent: invalid handshake (pstrlen: %hhu, pstr: %.*s)", pstrlen, 19, pstr.begin()));
			throw Exception("invalid handshake");
			}

		return true;
		%}

	function validate_message_length(len: uint32): bool
		%{
		if ( len > MSGLEN_LIMIT )
			throw Exception(fmt("message length prefix exceeds limit: %u > %u",
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
			BifEvent::generate_bittorrent_peer_handshake(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				bytestring_to_val(reserved),
				bytestring_to_val(info_hash),
				bytestring_to_val(peer_id));
			}

		connection()->bro_analyzer()->ProtocolConfirmation();

		return true;
		%}

	function deliver_keep_alive(): bool
		%{
		if ( ::bittorrent_peer_keep_alive )
			{
			BifEvent::generate_bittorrent_peer_keep_alive(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_choke(): bool
		%{
		if ( ::bittorrent_peer_choke )
			{
			BifEvent::generate_bittorrent_peer_choke(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_unchoke(): bool
		%{
		if ( ::bittorrent_peer_unchoke )
			{
			BifEvent::generate_bittorrent_peer_unchoke(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_interested(): bool
		%{
		if ( ::bittorrent_peer_interested )
			{
			BifEvent::generate_bittorrent_peer_interested(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_not_interested(): bool
		%{
		if ( ::bittorrent_peer_not_interested )
			{
			BifEvent::generate_bittorrent_peer_not_interested(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig());
			}

		return true;
		%}

	function deliver_have(piece_index: uint32): bool
		%{
		if ( ::bittorrent_peer_have )
			{
			BifEvent::generate_bittorrent_peer_have(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				piece_index);
			}

		return true;
		%}

	function deliver_bitfield(bitfield: const_bytestring): bool
		%{
		if ( ::bittorrent_peer_bitfield )
			{
			BifEvent::generate_bittorrent_peer_bitfield(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				bytestring_to_val(bitfield));
			}

		return true;
		%}

	function deliver_request(index: uint32, begin: uint32,
					length: uint32): bool
		%{
		if ( ::bittorrent_peer_request )
			{
			BifEvent::generate_bittorrent_peer_request(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
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
			BifEvent::generate_bittorrent_peer_piece(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
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
			BifEvent::generate_bittorrent_peer_cancel(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				index, begin, length);
			}

		return true;
		%}

	function deliver_port(listen_port: uint16): bool
		%{
		if ( ::bittorrent_peer_port )
			{
			BifEvent::generate_bittorrent_peer_port(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				new PortVal(listen_port, TRANSPORT_TCP));
			}

		return true;
		%}

	function deliver_unknown(id: uint8, data: const_bytestring): bool
		%{
		if ( ::bittorrent_peer_unknown )
			{
			BifEvent::generate_bittorrent_peer_unknown(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(),
				id,
				bytestring_to_val(data));
			}

		return true;
		%}
};
