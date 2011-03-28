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


# binpac-specific definitions

analyzer SSLRecordLayerAnalyzer {
	upflow = SSLRecordLayerFlow(true);
	downflow = SSLRecordLayerFlow(false);

	%member{
		SSLAnalyzer* ssl_analyzer_;
	%}

	%init{
		ssl_analyzer_ = 0;
	%}

	%eof{
		ssl_analyzer_->FlowEOF(true);
		ssl_analyzer_->FlowEOF(false);
	%}

	function set_ssl_analyzer(a : SSLAnalyzer) : void
		%{ ssl_analyzer_ = a; %}


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
