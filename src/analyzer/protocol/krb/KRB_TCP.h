// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/krb/krb_TCP_pac.h"

namespace zeek::analyzer::krb_tcp
	{

class KRB_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{

public:
	explicit KRB_Analyzer(Connection* conn);
	~KRB_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	StringValPtr GetAuthenticationInfo(const String* principal, const String* ciphertext,
	                                   const zeek_uint_t enctype)
		{
		return val_mgr->EmptyString();
		}

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new KRB_Analyzer(conn); }

protected:
	binpac::KRB_TCP::KRB_Conn* interp;
	bool had_gap;
	};

	} // namespace zeek::analyzer::krb_tcp
