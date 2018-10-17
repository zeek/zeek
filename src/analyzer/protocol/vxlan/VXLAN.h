#ifndef ANALYZER_PROTOCOL_VXLAN_VXLAN_H
#define ANALYZER_PROTOCOL_VXLAN_VXLAN_H

#include "analyzer/Analyzer.h"
#include "NetVar.h"
#include "Reporter.h"

namespace analyzer { namespace vxlan {

class VXLAN_Analyzer : public analyzer::Analyzer {
public:
	explicit VXLAN_Analyzer(Connection* conn) : Analyzer("VXLAN", conn),
	                                    valid_orig(false), valid_resp(false)
		{}

	~VXLAN_Analyzer() override
		{}

	void Done() override;

	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new VXLAN_Analyzer(conn); }

	/**
	 * Emits a weird only if the analyzer has previously been able to
	 * decapsulate a VXLAN packet in both directions or if *force* param is
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
/*	copied from Teredo, do we want this too for VXLAN?
    void Confirm()
		{
		if ( ! BifConst::Tunnel::delay_vxlan_confirmation ||
		     ( valid_orig && valid_resp ) )
			ProtocolConfirmation();
		}*/

protected:
	bool valid_orig;
	bool valid_resp;
};

class VXLANEncapsulation {
public:
	explicit VXLANEncapsulation(const VXLAN_Analyzer* ta)
		: inner_ip(0), analyzer(ta)
		{}

	/**
	 * Returns whether input data parsed as a valid VXLAN encapsulation type.
	 * If it was valid, the len argument is decremented appropriately.
	 */
	bool Parse(const u_char* data, int& len)
		{ return DoParse(data, len); }

	const u_char* InnerIP() const
		{ return inner_ip; }

	RecordVal* BuildVal(const IP_Hdr* inner) const;

protected:
	bool DoParse(const u_char* data, int& len);

	void Weird(const char* name) const
		{ analyzer->Weird(name); }

	const u_char* inner_ip;
	const VXLAN_Analyzer* analyzer;
};

} } // namespace analyzer::*

#endif
