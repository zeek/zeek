// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"

#include "krb_TCP_pac.h"

namespace zeek::analyzer::krb_tcp {

class KRB_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {

public:
	explicit KRB_Analyzer(zeek::Connection* conn);
	~KRB_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overriden from zeek::analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	zeek::StringValPtr GetAuthenticationInfo(const zeek::String* principal,
	                                         const zeek::String* ciphertext,
	                                         const bro_uint_t enctype)
		{ return zeek::val_mgr->EmptyString(); }

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new KRB_Analyzer(conn); }

protected:
	binpac::KRB_TCP::KRB_Conn* interp;
	bool had_gap;
};

} // namespace zeek::analyzer::krb_tcp

namespace analyzer::krb_tcp {

using KRB_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::krb_tcp::KRB_Analyzer.")]] = zeek::analyzer::krb_tcp::KRB_Analyzer;

} // namespace analyzer::krb_tcp
