// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <openssl/ocsp.h>

#include "X509Common.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek, file_analysis);

namespace zeek::file_analysis::detail {

class OCSP : public zeek::file_analysis::detail::X509Common {
public:
	bool DeliverStream(const u_char* data, uint64_t len) override;
	bool Undelivered(uint64_t offset, uint64_t len) override;
	bool EndOfFile() override;

	static zeek::file_analysis::Analyzer* InstantiateRequest(zeek::RecordValPtr args,
	                                                         zeek::file_analysis::File* file);
	static zeek::file_analysis::Analyzer* InstantiateReply(zeek::RecordValPtr args,
	                                                       zeek::file_analysis::File* file);

protected:
	OCSP(zeek::RecordValPtr args, zeek::file_analysis::File* file, bool request);

private:
	void ParseResponse(OCSP_RESPONSE*);
	void ParseRequest(OCSP_REQUEST*);
	void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) override;

	std::string ocsp_data;
	bool request = false; // true if ocsp request, false if reply
};

} // namespace zeek::file_analysis::detail

namespace file_analysis {

	using OCSP [[deprecated("Remove in v4.1. Use zeek::file_analysis::detail::OCSP.")]] = zeek::file_analysis::detail::OCSP;

} // namespace file_analysis
