// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_OCSP_H
#define FILE_ANALYSIS_OCSP_H

#include <string>

#include "Val.h"
#include "../File.h"
#include "Analyzer.h"

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

namespace file_analysis {

class OCSP_RESPVal;

class OCSP : public file_analysis::Analyzer {
public:
	virtual bool DeliverStream(const u_char* data, uint64 len);
	virtual bool Undelivered(uint64 offset, uint64 len);
	virtual bool EndOfFile();


	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

protected:
	OCSP(RecordVal* args, File* file, const string& ocsp_type);

private:
	void ParseResponse(OCSP_RESPVal *, const char* fid = 0);
	void ParseRequest(OCSP_REQUEST *, const char* fid = 0);

	std::string ocsp_data;
	std::string ocsp_type;
};

class OCSP_RESPVal: public OpaqueVal {
public:
	explicit OCSP_RESPVal(OCSP_RESPONSE *);
	~OCSP_RESPVal();
	OCSP_RESPONSE *GetResp() const;
protected:
	OCSP_RESPVal();
private:
	OCSP_RESPONSE *ocsp_resp;
	DECLARE_SERIAL(OCSP_RESPVal);
};

}

#endif
