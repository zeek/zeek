# $Id:$

# binpac analyzer representing the SSLv3 record layer
#
# This additional layering in the analyzer hierarchy is necessary due to
# fragmentation that can be introduced in the SSL record layer.

%include binpac.pac
%include bro.pac

analyzer SSLRecordLayer withcontext {
	analyzer : SSLRecordLayerAnalyzer;
	flow : SSLRecordLayerFlow;
};

%include ssl-defs.pac

%extern{
#include "ssl_pac.h"
using binpac::SSL::SSLAnalyzer;
%}

extern type const_bytestring;


type SSLPDU = record {
	head0 : uint8;
	head1 : uint8;
	head2 : uint8;
	head3 : uint8;
	head4 : uint8;
	fragment : bytestring &restofdata;
} &length = 5 + length, &byteorder = bigendian, &let {
	version : int =
		$context.analyzer.determine_ssl_version(head0, head1, head2);

	length : int = case version of {
		UNKNOWN_VERSION -> 0;
		SSLv20 -> (((head0 & 0x7f) << 8) | head1) - 3;
		default -> (head3 << 8) | head4;
	};

	fw : bool = case version of {
		UNKNOWN_VERSION ->
			$context.analyzer.forward_record(const_bytestring(),
				UNKNOWN_OR_V2_ENCRYPTED, UNKNOWN_VERSION,
				$context.flow.is_orig)
			&& $context.flow.discard_data();

	SSLv20 -> $context.analyzer.forward_v2_record(head2, head3, head4,
					fragment, $context.flow.is_orig);
	default -> $context.analyzer.forward_record(fragment, head0,
				(head1 << 8) | head2, $context.flow.is_orig);
	};
};

# binpac-specific definitions

analyzer SSLRecordLayerAnalyzer {
	upflow = SSLRecordLayerFlow(true);
	downflow = SSLRecordLayerFlow(false);

	%member{
		SSLAnalyzer* ssl_analyzer_;

		int ssl_version_;
		int record_length_;
	%}

	%init{
		ssl_analyzer_ = 0;
		ssl_version_ = UNKNOWN_VERSION;
		record_length_ = 0;
	%}

	%eof{
		ssl_analyzer_->FlowEOF(true);
		ssl_analyzer_->FlowEOF(false);
	%}

	function set_ssl_analyzer(a : SSLAnalyzer) : void
		%{ ssl_analyzer_ = a; %}

	function ssl_version() : int %{ return ssl_version_; %}
	function record_length() : int %{ return record_length_; %}

	function determine_ssl_version(head0 : uint8, head1 : uint8,
					head2 : uint8) : int
		%{
		if ( head0 >= 20 && head0 <= 23 &&
		     head1 == 0x03 && head2 <  0x03 )
			// This is most probably SSL version 3.
			ssl_version_ = (head1 << 8) | head2;

		else if ( head0 >= 128 && head2 < 5 && head2 != 3 )
			// Not very strong evidence, but we suspect
			// this to be SSLv2.
			ssl_version_ = SSLv20;

		else
			ssl_version_ = UNKNOWN_VERSION;

		return ssl_version_;
		%}

	function forward_record(fragment : const_bytestring, type : int,
				version : uint16, is_orig : bool) : bool
		%{
		return ssl_analyzer_->next_record(fragment, type,
							version, is_orig);
		%}

	function forward_v2_record(b1 : uint8, b2 : uint8, b3 : uint8,
					fragment : const_bytestring,
					is_orig : bool) : bool
		%{
		uint8* buffer = new uint8[2 + fragment.length()];

		// Byte 1 is the record type.
		buffer[0] = b2;
		buffer[1] = b3;

		memcpy(buffer + 2, fragment.begin(), fragment.length());
		const_bytestring bs(buffer, 2 + fragment.length());

		bool ret = ssl_analyzer_->next_record(bs, 300 + b1, SSLv20,
							is_orig);
		delete [] buffer;
		return ret;
		%}
};

flow SSLRecordLayerFlow(is_orig : bool) {
	flowunit = SSLPDU withcontext(connection, this);

	function discard_data() : bool
		%{
		flow_buffer_->DiscardData();
		return true;
		%}
};
