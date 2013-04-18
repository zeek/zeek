
#include "Teredo.h"
#include "TunnelEncapsulation.h"
#include "Conn.h"
#include "IP.h"
#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::teredo;

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
		Weird("truncated_Teredo");
		return false;
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
			Weird("truncated_Teredo_origin_indication");
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
			Weird("truncated_Teredo_authentication");
			return false;
			}

		uint8 id_len = data[2];
		uint8 au_len = data[3];
		uint16 tot_len = 4 + id_len + au_len + 8 + 1;

		if ( len < tot_len )
			{
			Weird("truncated_Teredo_authentication");
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
			Weird("truncated_IPv6_in_Teredo");
			return false;
			}

		// There's at least a possible IPv6 header, we'll decide what to do
		// later if the payload length field doesn't match the actual length
		// of the packet.
		inner_ip = data;
		return true;
		}

	return false;
	}

RecordVal* TeredoEncapsulation::BuildVal(const IP_Hdr* inner) const
	{
	static RecordType* teredo_hdr_type = 0;
	static RecordType* teredo_auth_type = 0;
	static RecordType* teredo_origin_type = 0;

	if ( ! teredo_hdr_type )
		{
		teredo_hdr_type = internal_type("teredo_hdr")->AsRecordType();
		teredo_auth_type = internal_type("teredo_auth")->AsRecordType();
		teredo_origin_type = internal_type("teredo_origin")->AsRecordType();
		}

	RecordVal* teredo_hdr = new RecordVal(teredo_hdr_type);

	if ( auth )
		{
		RecordVal* teredo_auth = new RecordVal(teredo_auth_type);
		uint8 id_len = *((uint8*)(auth + 2));
		uint8 au_len = *((uint8*)(auth + 3));
		uint64 nonce = ntohll(*((uint64*)(auth + 4 + id_len + au_len)));
		uint8 conf = *((uint8*)(auth + 4 + id_len + au_len + 8));
		teredo_auth->Assign(0, new StringVal(
		    new BroString(auth + 4, id_len, 1)));
		teredo_auth->Assign(1, new StringVal(
		    new BroString(auth + 4 + id_len, au_len, 1)));
		teredo_auth->Assign(2, new Val(nonce, TYPE_COUNT));
		teredo_auth->Assign(3, new Val(conf, TYPE_COUNT));
		teredo_hdr->Assign(0, teredo_auth);
		}

	if ( origin_indication )
		{
		RecordVal* teredo_origin = new RecordVal(teredo_origin_type);
		uint16 port = ntohs(*((uint16*)(origin_indication + 2))) ^ 0xFFFF;
		uint32 addr = ntohl(*((uint32*)(origin_indication + 4))) ^ 0xFFFFFFFF;
		teredo_origin->Assign(0, new PortVal(port, TRANSPORT_UDP));
		teredo_origin->Assign(1, new AddrVal(htonl(addr)));
		teredo_hdr->Assign(1, teredo_origin);
		}

	teredo_hdr->Assign(2, inner->BuildPktHdrVal());
	return teredo_hdr;
	}

void Teredo_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                    int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	if ( orig )
		valid_orig = false;
	else
		valid_resp = false;

	TeredoEncapsulation te(this);

	if ( ! te.Parse(data, len) )
		{
		ProtocolViolation("Bad Teredo encapsulation", (const char*) data, len);
		return;
		}

	const EncapsulationStack* e = Conn()->GetEncapsulation();

	if ( e && e->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("tunnel_depth", true);
		return;
		}

	IP_Hdr* inner = 0;
	int rslt = sessions->ParseIPPacket(len, te.InnerIP(), IPPROTO_IPV6, inner);

	if ( rslt > 0 )
		{
		if ( inner->NextProto() == IPPROTO_NONE && inner->PayloadLen() == 0 )
			// Teredo bubbles having data after IPv6 header isn't strictly a
			// violation, but a little weird.
			Weird("Teredo_bubble_with_payload", true);
		else
			{
			delete inner;
			ProtocolViolation("Teredo payload length", (const char*) data, len);
			return;
			}
		}

	if ( rslt == 0 || rslt > 0 )
		{
		if ( orig )
			valid_orig = true;
		else
			valid_resp = true;

		if ( BifConst::Tunnel::yielding_teredo_decapsulation &&
		     ! ProtocolConfirmed() )
			{
			// Only confirm the Teredo tunnel and start decapsulating packets
			// when no other sibling analyzer thinks it's already parsing the
			// right protocol.
			bool sibling_has_confirmed = false;
			if ( Parent() )
				{
				LOOP_OVER_GIVEN_CONST_CHILDREN(i, Parent()->GetChildren())
					{
					if ( (*i)->ProtocolConfirmed() )
						{
						sibling_has_confirmed = true;
						break;
						}
					}
				}

			if ( ! sibling_has_confirmed )
				Confirm();
			else
				{
				delete inner;
				return;
				}
			}
		else
			// Aggressively decapsulate anything with valid Teredo encapsulation.
			Confirm();
		}

	else
		{
		delete inner;
		ProtocolViolation("Truncated Teredo", (const char*) data, len);
		return;
		}

	Val* teredo_hdr = 0;

	if ( teredo_packet )
		{
		teredo_hdr = te.BuildVal(inner);
		Conn()->Event(teredo_packet, 0, teredo_hdr);
		}

	if ( te.Authentication() && teredo_authentication )
		{
		teredo_hdr = teredo_hdr ? teredo_hdr->Ref() : te.BuildVal(inner);
		Conn()->Event(teredo_authentication, 0, teredo_hdr);
		}

	if ( te.OriginIndication() && teredo_origin_indication )
		{
		teredo_hdr = teredo_hdr ? teredo_hdr->Ref() : te.BuildVal(inner);
		Conn()->Event(teredo_origin_indication, 0, teredo_hdr);
		}

	if ( inner->NextProto() == IPPROTO_NONE && teredo_bubble )
		{
		teredo_hdr = teredo_hdr ? teredo_hdr->Ref() : te.BuildVal(inner);
		Conn()->Event(teredo_bubble, 0, teredo_hdr);
		}

	EncapsulatingConn ec(Conn(), BifEnum::Tunnel::TEREDO);

	sessions->DoNextInnerPacket(network_time, 0, inner, e, ec);
	}
