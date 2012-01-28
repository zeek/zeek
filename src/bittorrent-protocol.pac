# This code contributed by Nadi Sarrar.

enum BitTorrent_peer_msg_type {
	TYPE_CHOKE           = 0,
	TYPE_UNCHOKE         = 1,
	TYPE_INTERESTED      = 2,
	TYPE_NOT_INTERESTED  = 3,
	TYPE_HAVE            = 4,
	TYPE_BITFIELD        = 5,
	TYPE_REQUEST         = 6,
	TYPE_PIECE           = 7,
	TYPE_CANCEL          = 8,
	TYPE_PORT            = 9,
};

type BitTorrent_Handshake = record {
	pstrlen:   uint8;
	pstr:      bytestring &length = 19;
	reserved:  bytestring &length = 8;
	info_hash: bytestring &length = 20;
	peer_id:   bytestring &length = 20;

} &length = 68, &let {
	validate: bool = $context.flow.validate_handshake(pstrlen, pstr);
	#incoffsetffset: bool =
	#	$context.flow.increment_next_message_offset(true, 68);
	deliver: bool =
		$context.flow.deliver_handshake(reserved, info_hash, peer_id);
};

type BitTorrent_KeepAlive = empty &let {
	deliver: bool = $context.flow.deliver_keep_alive();
};

type BitTorrent_Choke = empty &let {
	deliver: bool = $context.flow.deliver_choke();
};

type BitTorrent_Unchoke = empty &let {
	deliver: bool = $context.flow.deliver_unchoke();
};

type BitTorrent_Interested = empty &let {
	deliver: bool = $context.flow.deliver_interested();
};

type BitTorrent_NotInterested = empty &let {
	deliver: bool = $context.flow.deliver_not_interested();
};

type BitTorrent_Have = record {
	piece_index: uint32;
} &let {
	deliver: bool = $context.flow.deliver_have(piece_index);
};

type BitTorrent_Bitfield(len: uint32) = record {
	bitfield: bytestring &length = len;
} &let {
	deliver: bool = $context.flow.deliver_bitfield(bitfield);
};

type BitTorrent_Request = record {
	index:  uint32;
	begin:  uint32;
	length: uint32;
} &let {
	deliver: bool = $context.flow.deliver_request(index, begin, length);
};

type BitTorrent_PieceHeader(len: uint32) = record {
	index: uint32;
	begin: uint32;
} &let {
	#incoffset: bool =
	#	$context.flow.increment_next_message_offset(true, len + 5);
};

type BitTorrent_Piece(len: uint32) = record {
	header: BitTorrent_PieceHeader(len);
	:       bytestring &length = len - 8;
} &let {
	deliver: bool = $context.flow.deliver_piece(header.index,
							header.begin, len - 8);
};

type BitTorrent_Cancel = record {
	index:  uint32;
	begin:  uint32;
	length: uint32;
} &let {
	deliver: bool = $context.flow.deliver_cancel(index, begin, length);
};

type BitTorrent_Port = record {
	listen_port: uint16;
} &let {
	deliver: bool = $context.flow.deliver_port(listen_port);
};

type BitTorrent_Unknown(id: uint8, len: uint32) = record {
	data: bytestring &length = len;
} &let {
	deliver: bool = $context.flow.deliver_unknown(id, data);
};

type BitTorrent_MessageID(len: uint32) = record {
	id:   uint8;
	data: case id of {
		TYPE_CHOKE          -> choke: BitTorrent_Choke;
		TYPE_UNCHOKE        -> unchoke: BitTorrent_Unchoke;
		TYPE_INTERESTED     -> interested: BitTorrent_Interested;
		TYPE_NOT_INTERESTED -> not_interested: BitTorrent_NotInterested;
		TYPE_HAVE           -> have: BitTorrent_Have;
		TYPE_BITFIELD       -> bitfield: BitTorrent_Bitfield(len - 1);
		TYPE_REQUEST        -> request: BitTorrent_Request;
		TYPE_PIECE          -> piece: BitTorrent_Piece(len - 1);
		TYPE_CANCEL         -> cancel: BitTorrent_Cancel;
		TYPE_PORT           -> port: BitTorrent_Port;
		default             -> unknown: BitTorrent_Unknown(id, len - 1);
	};
};

type BitTorrent_MessageLength = record {
	len: uint32;
} &let {
	validate: bool = $context.flow.validate_message_length(len);
};

type BitTorrent_Message = record {
	len:  BitTorrent_MessageLength;
	data: case len.len of {
		0       -> keep_alive: BitTorrent_KeepAlive;
		default -> message_id: BitTorrent_MessageID(len.len);
	};
} &length = 4 + len.len, &let {
	#incoffset: bool = $context.flow.increment_next_message_offset(
	#			len.len == 0 || message_id.id != TYPE_PIECE,
	#			4 + len.len);
};

type BitTorrent_PDU = case $context.flow.is_handshake_delivered() of {
	false -> handshake: BitTorrent_Handshake;
	true  -> message: BitTorrent_Message;
} &byteorder = bigendian;
