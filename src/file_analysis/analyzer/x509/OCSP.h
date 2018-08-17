// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_OCSP_H
#define FILE_ANALYSIS_OCSP_H

#include <string>

#include "Val.h"
#include "../File.h"
#include "Analyzer.h"
#include "X509Common.h"

#include <openssl/ocsp.h>

namespace file_analysis {

class OCSP_RESPVal;

class OCSP : public file_analysis::X509Common {
public:
	bool DeliverStream(const u_char* data, uint64 len) override;
	bool Undelivered(uint64 offset, uint64 len) override;
	bool EndOfFile() override;

	static file_analysis::Analyzer* InstantiateRequest(RecordVal* args, File* file);
	static file_analysis::Analyzer* InstantiateReply(RecordVal* args, File* file);

protected:
	OCSP(RecordVal* args, File* file, bool request);

private:
	void ParseResponse(OCSP_RESPVal*, const char* fid = 0);
	void ParseRequest(OCSP_REQUEST*, const char* fid = 0);
	void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) override;

	std::string ocsp_data;
	bool request = false; // true if ocsp request, false if reply
};

class OCSP_RESPVal: public OpaqueVal {
public:
	explicit OCSP_RESPVal(OCSP_RESPONSE *);
	~OCSP_RESPVal() override;
	OCSP_RESPONSE *GetResp() const;
protected:
	OCSP_RESPVal();
private:
	OCSP_RESPONSE *ocsp_resp;
	DECLARE_SERIAL(OCSP_RESPVal);
};

}

#endif
