#include "Teredo.h"
#include "IP.h"
#include "Reporter.h"

void Teredo_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

bool TeredoEncapsulation::DoParse(const u_char* data, int& len,
                                  bool found_origin, bool found_auth)
	{
	if ( len < 2 )
		{
		reporter->Weird(conn, "truncated_Teredo");
		}

	uint16 tag = ntohs((*((const uint16*)data)));

	if ( tag == 0 )
		{
		// Origin Indication
		if ( found_origin )
			// can't have multiple origin indications
			return false;

		if ( len < 8 )
			{
			reporter->Weird(conn, "truncated_Teredo_origin_indication");
			return false;
			}

		origin_indication = data;
		len -= 8;
		data += 8;
		return DoParse(data, len, true, found_auth);
		}
	else if ( tag == 1 )
		{
		// Authentication
		if ( found_origin || found_auth )
			// can't have multiple authentication headers and can't come after
			// an origin indication
			return false;

		if ( len < 4 )
			{
			reporter->Weird(conn, "truncated_Teredo_authentication");
			return false;
			}

		uint8 id_len = data[2];
		uint8 au_len = data[3];
		uint16 tot_len = 4 + id_len + au_len + 8 + 1;

		if ( len < tot_len )
			{
			reporter->Weird(conn, "truncated_Teredo_authentication");
			return false;
			}

		auth = data;
		len -= tot_len;
		data += tot_len;
		return DoParse(data, len, found_origin, true);
		}
	else if ( ((tag & 0xf000)>>12) == 6 )
		{
		// IPv6
		if ( len < 40 )
			{
			reporter->Weird(conn, "truncated_IPv6_in_Teredo");
			return false;
			}

		if ( len - 40 != ntohs(((const struct ip6_hdr*)data)->ip6_plen) )
			{
			reporter->Weird(conn, "Teredo_payload_len_mismatch");
			return false;
			}

		inner_ip = data;
		return true;
		}

	return false;
	}

void Teredo_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                    int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	const Encapsulation* e = Conn()->GetEncapsulation();

	if ( e && e->Depth() >= BifConst::Tunnel::max_depth )
		{
		reporter->Weird(Conn(), "tunnel_depth");
		return;
		}

	TeredoEncapsulation te(Conn());

	if ( ! te.Parse(data, len) )
		{
		ProtocolViolation("Invalid Teredo encapsulation", (const char*)data,
		                  len);
		return;
		}

	ProtocolConfirmation();

	// TODO: raise Teredo-specific events

	Encapsulation* outer = new Encapsulation(e);
	EncapsulatingConn ec(Conn(), BifEnum::Tunnel::TEREDO);
	outer->Add(ec);

	sessions->DoNextInnerPacket(network_time, 0, len, te.InnerIP(),
	                            IPPROTO_IPV6, outer);
	delete outer;
	}
