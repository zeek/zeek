# Netware Core Protocol

%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer NCP withcontext {};

type ncp_request(length: uint32) = record {
	data		: uint8[length];
} &let {
	function	= length > 0 ? data[0] : 0;
	subfunction	= length > 1 ? data[1] : 0;
};

type ncp_reply(length: uint32) = record {
	completion_code	: uint8;
	conn_status 	: uint8;
	data		: uint8[length - 2];
};

type ncp_frame(is_orig: bool, length: uint32) = record {
	frame_type	: uint16;
	seq		: uint8;
	conn_low	: uint8;
	task		: uint8;
	conn_high	: uint8;
	body		: case is_orig of
		{
		true -> request	: ncp_request(body_length);
		false -> reply	: ncp_reply(body_length);
		} &requires(body_length);
} &let {
	body_length = length - offsetof(body);
};

type ncp_over_tcpip_req_hdr = record {
	version		: uint32;
	reply_buf_size	: uint32;
};

type ncp_over_tcpip_frame(is_orig: bool) = record {
	signature	: uint32;
	length		: uint32;
	aux		: case is_orig of
		{
		true -> aux_req		: ncp_over_tcpip_req_hdr;
		false -> aux_reply	: empty;
		};
	ncp		: ncp_frame(is_orig, length - offsetof(ncp));
} &byteorder = bigendian,
  &length = length,
  &check( ncp.frame_type == 0x1111 ||
          ncp.frame_type == 0x2222 ||
          ncp.frame_type == 0x3333 ||
          ncp.frame_type == 0x5555 ||
          ncp.frame_type == 0x7777 ||
          ncp.frame_type == 0x9999 );
