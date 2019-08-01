#ifndef ANALYZER_PROTOCOL_OPENVPN_DTLS_H
#define ANALYZER_PROTOCOL_OPENVPN_DTLS_H

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"

namespace analyzer { namespace ssl { class SSL_Analyzer; } }

namespace binpac { namespace openvpn { class OpenVPN_Conn; } }

namespace analyzer { namespace openvpn {

class OpenVPN_Analyzer : public analyzer::Analyzer {
public:
	explicit OpenVPN_Analyzer(Connection* conn);
	~OpenVPN_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen) override;
	void EndOfData(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new OpenVPN_Analyzer(conn); }

	void ForwardSSLData(int len, const u_char* data, bool orig);

protected:
	binpac::openvpn::OpenVPN_Conn* interp;
	analyzer::ssl::SSL_Analyzer* ssl = nullptr;
};

} } // namespace analyzer::*

#endif
