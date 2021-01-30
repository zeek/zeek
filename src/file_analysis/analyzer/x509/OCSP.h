// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <openssl/ocsp.h>

#include "zeek/file_analysis/analyzer/x509/X509Common.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek, file_analysis);

namespace zeek::file_analysis::detail {

class OCSP : public file_analysis::detail::X509Common {
public:
	bool DeliverStream(const u_char* data, uint64_t len) override;
	bool Undelivered(uint64_t offset, uint64_t len) override;
	bool EndOfFile() override;

	static file_analysis::Analyzer* InstantiateRequest(RecordValPtr args,
	                                                   file_analysis::File* file);
	static file_analysis::Analyzer* InstantiateReply(RecordValPtr args,
	                                                 file_analysis::File* file);

protected:
	OCSP(RecordValPtr args, file_analysis::File* file, bool request);

private:
	void ParseResponse(OCSP_RESPONSE*);
	void ParseRequest(OCSP_REQUEST*);
	void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) override;

	std::string ocsp_data;
	bool request = false; // true if ocsp request, false if reply
};

} // namespace zeek::file_analysis::detail
