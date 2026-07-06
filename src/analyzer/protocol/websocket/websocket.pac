# See the file "COPYING" in the main distribution directory for copyright.

%include binpac.pac
%include zeek.pac

%header{
#include <zlib.h>
%}

%extern{
#include <array>

#include "zeek/analyzer/protocol/websocket/consts.bif.h"
#include "zeek/analyzer/protocol/websocket/events.bif.h"
%}

analyzer WebSocket withcontext {
	connection: WebSocket_Conn;
	flow: WebSocket_Flow;
};

connection WebSocket_Conn(zeek_analyzer: ZeekAnalyzer) {
	upflow = WebSocket_Flow(true);
	downflow = WebSocket_Flow(false);
	
	%member{
		bool permessage_compression_enabled_;	
		z_stream* z_strm_;
	%}

	%init{
		permessage_compression_enabled_ = false;
		z_strm_ = nullptr;
	%}
		
	%cleanup{
		if( z_strm_ )
			{
			inflateEnd(z_strm_);
			delete z_strm_;
			}
	%}

	function EnablePerMessageCompression(): bool
		%{
		permessage_compression_enabled_ = true;
		//fprintf(stderr, "DEBUG: BinPAC EnablePerMessageCompression flag set to TRUE!\n");
		return true;
		%}
	function HasPerMessageCompressionEnabled(): bool
		%{
		return permessage_compression_enabled_;
		%}

	function DecompressPayload(data: const_byteptr, len: int, is_orig: bool): bool
		%{
		// Initialise zlib
		if ( ! z_strm_ )
			{
			z_strm_ = new z_stream;
			z_strm_->zalloc = Z_NULL;
			z_strm_->zfree = Z_NULL;
			z_strm_->opaque = Z_NULL;

			// -15 is magic number for zlib to process raw DEFLATE 
			// without headers.
			if ( inflateInit2(z_strm_, -15) != Z_OK)
				return false;	
			}
		// Append 4-byte to payload according to RFC 7692
		int input_len = len + 4;
		unsigned char* input_buf = new unsigned char [input_len];
		memcpy(input_buf, data, len);
		input_buf[len] = 0x00;
		input_buf[len+1] = 0x00;
		input_buf[len+2] = 0xff;
		input_buf[len+3] = 0xff;

		z_strm_->avail_in = input_len;
		z_strm_->next_in = input_buf;
		
		// Decompress payload in chunks
		unsigned char out_buf[4096];
		
		do{
			z_strm_->avail_out = sizeof(out_buf);
			z_strm_->next_out = out_buf;
			
			int ret = inflate(z_strm_, Z_SYNC_FLUSH);
			if ( ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR )
				{
				// Decompression failed
				delete[] input_buf;
				return false;
				}
			
			int have = sizeof(out_buf) - z_strm_->avail_out;
			if ( have > 0 )
				{
				if ( websocket_frame_data )
					{
						zeek::BifEvent::enqueue_websocket_frame_data(
							zeek_analyzer(),
							zeek_analyzer()->Conn(),
							is_orig,
							zeek::make_intrusive<zeek::StringVal>(have, (const char*)out_buf));
					}
				}	
		} while(z_strm_->avail_out == 0);
		delete[] input_buf;
		return true;

		%}
};

%include websocket-protocol.pac
%include websocket-analyzer.pac
