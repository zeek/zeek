#pragma once

#include "analyzer/Analyzer.h"
#include "NetVar.h"
#include "Reporter.h"

namespace analyzer { namespace teredo {

class Teredo_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit Teredo_Analyzer(Connection* conn) : Analyzer("TEREDO", conn),
	                                    valid_orig(false), valid_resp(false)
		{}

	~Teredo_Analyzer() override
		{}

	void Done() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Teredo_Analyzer(conn); }

	/**
	 * Emits a weird only if the analyzer has previously been able to
	 * decapsulate a Teredo packet in both directions or if *force* param is
	 * set, since otherwise the weirds could happen frequently enough to be less
	 * than helpful.  The *force* param is meant for cases where just one side
	 * has a valid encapsulation and so the weird would be informative.
	 */
	void Weird(const char* name, bool force = false) const
		{
		if ( ProtocolConfirmed() || force )
			reporter->Weird(Conn(), name);
		}

	/**
	 * If the delayed confirmation option is set, then a valid encapsulation
	 * seen from both end points is required before confirming.
	 */
	void Confirm()
		{
		if ( ! zeek::BifConst::Tunnel::delay_teredo_confirmation ||
		     ( valid_orig && valid_resp ) )
			ProtocolConfirmation();
		}

protected:
	bool valid_orig;
	bool valid_resp;
};

class TeredoEncapsulation {
public:
	explicit TeredoEncapsulation(const Teredo_Analyzer* ta)
		: inner_ip(nullptr), origin_indication(nullptr), auth(nullptr), analyzer(ta)
		{}

	/**
	 * Returns whether input data parsed as a valid Teredo encapsulation type.
	 * If it was valid, the len argument is decremented appropriately.
	 */
	bool Parse(const u_char* data, int& len)
		{ return DoParse(data, len, false, false); }

	const u_char* InnerIP() const
		{ return inner_ip; }

	const u_char* OriginIndication() const
		{ return origin_indication; }

	const u_char* Authentication() const
		{ return auth; }

	zeek::RecordValPtr BuildVal(const IP_Hdr* inner) const;

protected:
	bool DoParse(const u_char* data, int& len, bool found_orig, bool found_au);

	void Weird(const char* name) const
		{ analyzer->Weird(name); }

	const u_char* inner_ip;
	const u_char* origin_indication;
	const u_char* auth;
	const Teredo_Analyzer* analyzer;
};

} } // namespace analyzer::*
