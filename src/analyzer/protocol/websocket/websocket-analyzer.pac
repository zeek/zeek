# See the file "COPYING" in the main distribution directory for copyright.
#
# The WebSocket analyzer.
#

refine flow WebSocket_Flow += {

	function process_message(msg: WebSocket_Message): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();

		if ( websocket_message )
			{
			zeek::BifEvent::enqueue_websocket_message(connection()->zeek_analyzer(),
			                                          connection()->zeek_analyzer()->Conn(),
			                                          is_orig(),
			                                          ${msg.opcode});
			}

		return true;
		%}

	function process_header(hdr: WebSocket_FrameHeader): bool
		%{
		if ( websocket_frame )
			{
			zeek::BifEvent::enqueue_websocket_frame(connection()->zeek_analyzer(),
			                                        connection()->zeek_analyzer()->Conn(),
			                                        is_orig(),
			                                        ${hdr.fin},
			                                        ${hdr.reserved},
			                                        ${hdr.opcode},
			                                        ${hdr.payload_len});
			}

		return true;
		%}

	function process_payload_close(close: WebSocket_FramePayloadClose): bool
		%{
		if ( websocket_close )
			{
			const auto& reason = ${close.reason};
			auto reason_val = zeek::make_intrusive<zeek::StringVal>(reason.length(),
			                                                        reinterpret_cast<const char*>(reason.data()));
			zeek::BifEvent::enqueue_websocket_close(connection()->zeek_analyzer(),
			                                        connection()->zeek_analyzer()->Conn(),
			                                        is_orig(),
			                                        ${close.status},
			                                        reason_val);
			}

		return true;
		%}

	function process_empty_close(hdr: WebSocket_FrameHeader): bool
		%{
		if ( websocket_close )
			{
			zeek::BifEvent::enqueue_websocket_close(connection()->zeek_analyzer(),
			                                        connection()->zeek_analyzer()->Conn(),
			                                        is_orig(),
			                                        0, /* use placeholder status */
			                                        zeek::val_mgr->EmptyString());
			}

		return true;
		%}

	function process_payload_chunk(chunk: WebSocket_FramePayloadChunk): bool
		%{
		auto& data = ${chunk.data};

		// In-place unmasking if frame payload is masked.
		if ( has_mask_ )
			{
			auto *d = data.data();
			for ( int i = 0; i < data.length(); i++ )
				d[i] = d[i] ^ masking_key_[masking_key_idx_++ % masking_key_.size()];
			}

		if ( websocket_frame_data )
			{
			auto data_val = zeek::make_intrusive<zeek::StringVal>(data.length(), reinterpret_cast<const char*>(data.data()));
			zeek::BifEvent::enqueue_websocket_frame_data(connection()->zeek_analyzer(),
			                                             connection()->zeek_analyzer()->Conn(),
			                                             is_orig(),
			                                             std::move(data_val));
			}

		// Forward text and binary data to downstream analyzers.
		if ( effective_opcode_ == OPCODE_TEXT || effective_opcode_ == OPCODE_BINARY)
			connection()->zeek_analyzer()->ForwardStream(data.length(),
			                                             data.data(),
			                                             is_orig());

		return true;
		%}
};

refine typeattr WebSocket_Message += &let {
	proc_message = $context.flow.process_message(this);
};

refine typeattr WebSocket_FrameHeader += &let {
	proc_header = $context.flow.process_header(this);
};

refine typeattr WebSocket_FramePayloadClose += &let {
	proc_payload_close = $context.flow.process_payload_close(this);
};
