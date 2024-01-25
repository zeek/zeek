# See the file "COPYING" in the main distribution directory for copyright.
#
# The WebSocket protocol.
#
# https://datatracker.ietf.org/doc/html/rfc6455

enum Opcodes {
	OPCODE_CONTINUATION = 0x00,
	OPCODE_TEXT         = 0x01,
	OPCODE_BINARY       = 0x02,
	OPCODE_CLOSE        = 0x08,
	OPCODE_PING         = 0x09,
	OPCODE_PONG         = 0x0a,
}

type WebSocket_FrameHeader(first_frame: bool)  = record {
	first2: uint16 &enforce((first_frame && opcode != 0) || (!first_frame && opcode == 0));
	maybe_more_len: case payload_len1 of {
		126 -> payload_len2: uint16;
		127 -> payload_len8: uint64;
		default -> short_len: empty;
	};

	maybe_masking_key: case has_mask of {
		true -> masking_key: bytestring &length=4;
		false -> no_masking_key: empty;
	};
} &let {
	fin: bool = (first2 & 0x8000) ? true : false;
	reserved: uint8 = ((first2 & 0x7000) >> 12);
	opcode: uint8 = (first2 & 0x0f00) >> 8;
	payload_len1: uint8 = (first2 & 0x007f);
	has_mask: bool = (first2 & 0x0080) ? true : false;

	# Derived fields.
	rest_header_len: uint64 = (has_mask ? 4 : 0) + (payload_len1 < 126 ? 0 : (payload_len1 == 126 ? 2 : 8));
	payload_len: uint64 = payload_len1 < 126 ? payload_len1 : (payload_len1 == 126 ? payload_len2 : payload_len8);

	new_frame_payload = $context.flow.new_frame_payload(this);
} &length=2+rest_header_len;

type WebSocket_FramePayloadClose = record {
	status: uint16;
	reason: bytestring &restofdata;
} &byteorder=bigendian;

type WebSocket_FramePayloadChunk(len: uint64, hdr: WebSocket_FrameHeader) = record {
	data: bytestring &restofdata;
} &let {
	consumed_payload = $context.flow.consumed_chunk_len(len);
	payload_chunk = $context.flow.process_payload_chunk(this);  # unmasks if needed
	close_payload: WebSocket_FramePayloadClose withinput data &length=len &if(hdr.opcode == OPCODE_CLOSE);
} &length=len;

type WebSocket_Frame(first_frame: bool, msg: WebSocket_Message) = record {
	hdr: WebSocket_FrameHeader(first_frame);

	# This is implementing frame payload chunking so that we do not
	# attempt to buffer huge frames and forward data to downstream
	# analyzers in chunks.
	#
	# I tried &chunked and it didn't do anything very useful.
	chunks: WebSocket_FramePayloadChunk($context.flow.next_chunk_len(), hdr)[]
	        &until($context.flow.remaining_frame_payload_len() == 0)
	        &transient;
} &let {
	# If we find a close frame without payload, raise the event here
	# as the close won't have been parsed via chunks.
	empty_close = $context.flow.process_empty_close(hdr) &if(hdr.opcode == OPCODE_CLOSE) && hdr.payload_len == 0;
};

type WebSocket_Message = record {
	first_frame: WebSocket_Frame(true, this);
	optional_more_frames: case first_frame.hdr.fin of {
		true -> no_more_frames: empty;
		false -> more_frames: WebSocket_Frame(false, this)[] &until($element.hdr.fin);
	};
} &let {
	opcode = first_frame.hdr.opcode;
} &byteorder=bigendian;

flow WebSocket_Flow(is_orig: bool) {
	flowunit = WebSocket_Message withcontext(connection, this);

	%member{
		bool has_mask_;
		uint64_t masking_key_idx_;
		uint64_t frame_payload_len_;
		std::array<uint8_t, 4> masking_key_;
		uint8_t effective_opcode_;
	%}

	%init{
		has_mask_ = false;
		masking_key_idx_ = 0;
		frame_payload_len_ = 0;
		effective_opcode_ = OPCODE_CONTINUATION;
	%}

	function new_frame_payload(hdr: WebSocket_FrameHeader): uint64
		%{
		if ( frame_payload_len_ > 0 )
			connection()->zeek_analyzer()->Weird("websocket_frame_not_consumed");

		// Update the effective_opcode for all frames
		// following this one in the message.
		if ( ${hdr.first_frame} )
			effective_opcode_ = ${hdr.opcode};

		frame_payload_len_ = ${hdr.payload_len};
		has_mask_ = ${hdr.has_mask};
		masking_key_idx_ = 0;
		if ( has_mask_ ) {
			assert(${hdr.masking_key}.length() == static_cast<int>(masking_key_.size()));
			memcpy(masking_key_.data(), ${hdr.masking_key}.data(), masking_key_.size());
		}
		return frame_payload_len_;
		%}

	function remaining_frame_payload_len(): uint64
		%{
		return frame_payload_len_;
		%}

	function consumed_chunk_len(len: uint64): uint64
		%{
		if ( len > frame_payload_len_ ) {
			connection()->zeek_analyzer()->Weird("websocket_frame_consuming_too_much");
			len = frame_payload_len_;
		}

		frame_payload_len_ -= len;
		return len;
		%}

	function next_chunk_len(): uint64
		%{
		uint64_t len = frame_payload_len_;

		// It would be somewhat nicer if we could just consume
		// anything still left to consume from the current packet,
		// but couldn't figure out if that information can be pulled
		// flow buffer.
		if ( len > zeek::BifConst::WebSocket::payload_chunk_size )
			len = zeek::BifConst::WebSocket::payload_chunk_size;

		return len;
		%}
};
