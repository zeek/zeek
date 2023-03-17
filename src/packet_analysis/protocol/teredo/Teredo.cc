#include "zeek/packet_analysis/protocol/teredo/Teredo.h"

#include "zeek/Conn.h"
#include "zeek/IP.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/ZeekString.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"
#include "zeek/packet_analysis/protocol/teredo/events.bif.h"

namespace zeek::packet_analysis::teredo
	{

namespace detail
	{

bool TeredoEncapsulation::DoParse(const u_char* data, size_t& len, bool found_origin,
                                  bool found_auth)
	{
	if ( len < 2 )
		{
		Weird("truncated_Teredo");
		return false;
		}

	uint16_t tag = ntohs((*((const uint16_t*)data)));

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

		uint8_t id_len = data[2];
		uint8_t au_len = data[3];
		uint16_t tot_len = 4 + id_len + au_len + 8 + 1;

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

	else if ( ((tag & 0xf000) >> 12) == 6 )
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

RecordValPtr TeredoEncapsulation::BuildVal(const std::shared_ptr<IP_Hdr>& inner) const
	{
	static auto teredo_hdr_type = id::find_type<RecordType>("teredo_hdr");
	static auto teredo_auth_type = id::find_type<RecordType>("teredo_auth");
	static auto teredo_origin_type = id::find_type<RecordType>("teredo_origin");

	auto teredo_hdr = make_intrusive<RecordVal>(teredo_hdr_type);

	if ( auth )
		{
		auto teredo_auth = make_intrusive<RecordVal>(teredo_auth_type);
		uint8_t id_len = *((uint8_t*)(auth + 2));
		uint8_t au_len = *((uint8_t*)(auth + 3));
		uint64_t nonce = ntohll(*((uint64_t*)(auth + 4 + id_len + au_len)));
		uint8_t conf = *((uint8_t*)(auth + 4 + id_len + au_len + 8));
		teredo_auth->Assign(0, new String(auth + 4, id_len, true));
		teredo_auth->Assign(1, new String(auth + 4 + id_len, au_len, true));
		teredo_auth->Assign(2, nonce);
		teredo_auth->Assign(3, conf);
		teredo_hdr->Assign(0, std::move(teredo_auth));
		}

	if ( origin_indication )
		{
		auto teredo_origin = make_intrusive<RecordVal>(teredo_origin_type);
		uint16_t port = ntohs(*((uint16_t*)(origin_indication + 2))) ^ 0xFFFF;
		uint32_t addr = ntohl(*((uint32_t*)(origin_indication + 4))) ^ 0xFFFFFFFF;
		teredo_origin->Assign(0, val_mgr->Port(port, TRANSPORT_UDP));
		teredo_origin->Assign(1, make_intrusive<AddrVal>(htonl(addr)));
		teredo_hdr->Assign(1, std::move(teredo_origin));
		}

	teredo_hdr->Assign(2, inner->ToPktHdrVal());
	return teredo_hdr;
	}

	} // namespace detail

TeredoAnalyzer::TeredoAnalyzer() : zeek::packet_analysis::Analyzer("TEREDO")
	{
	// The pattern matching below is based on this old DPD signature
	// signature dpd_teredo {
	// 	ip-proto = udp
	// 	payload
	// /^(\x00\x00)|(\x00\x01)|([\x60-\x6f].{7}((\x20\x01\x00\x00)).{28})|([\x60-\x6f].{23}((\x20\x01\x00\x00))).{12}/
	// 	enable "teredo"
	// 	}

	pattern_re = std::make_unique<zeek::detail::Specific_RE_Matcher>(zeek::detail::MATCH_EXACTLY,
	                                                                 true);
	pattern_re->AddPat("^([\\x60-\\x6f].{7}((\\x20\\x01\\x00\\x00)).{28})"
	                   "|([\\x60-\\x6f].{23}((\\x20\\x01\\x00\\x00))).{12}");
	pattern_re->Compile();
	}

bool TeredoAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! BifConst::Tunnel::enable_teredo )
		return false;

	// Teredo always comes from a UDP connection, which means that session should always
	// be valid and always be a connection. Store this off for the span of the
	// processing so that it can be used for other things. Return a weird if we didn't
	// have a session stored.
	if ( ! packet->session )
		{
		Analyzer::Weird("teredo_missing_connection");
		return false;
		}
	else if ( AnalyzerViolated(packet->session) )
		return false;

	if ( packet->encap && packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Analyzer::Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	conn = static_cast<Connection*>(packet->session);
	zeek::detail::ConnKey conn_key = conn->Key();

	OrigRespMap::iterator or_it = orig_resp_map.find(conn_key);
	if ( or_it == orig_resp_map.end() )
		or_it = orig_resp_map.insert(or_it, {conn_key, {}});

	detail::TeredoEncapsulation te(this);
	if ( ! te.Parse(data, len) )
		{
		AnalyzerViolation("Bad Teredo encapsulation", conn, (const char*)data, len);
		return false;
		}

	// TODO: i'm not sure about this. on the one hand, we do some error checking with the result
	// but on the other hand we duplicate this work here. maybe this header could just be stored
	// and reused in the IP analyzer somehow?
	std::shared_ptr<IP_Hdr> inner = nullptr;
	auto result = packet_analysis::IP::ParsePacket(len, te.InnerIP(), IPPROTO_IPV6, inner);
	if ( result == packet_analysis::IP::ParseResult::CaplenTooLarge )
		{
		if ( inner->NextProto() == IPPROTO_NONE && inner->PayloadLen() == 0 )
			// Teredo bubbles having data after IPv6 header isn't strictly a
			// violation, but a little weird.
			Weird("Teredo_bubble_with_payload", true);
		else
			{
			AnalyzerViolation("Teredo payload length", conn, (const char*)data, len);
			return false;
			}
		}

	if ( result == packet_analysis::IP::ParseResult::CaplenTooSmall ||
	     result == packet_analysis::IP::ParseResult::BadProtocol )
		{
		AnalyzerViolation("Truncated Teredo or invalid inner IP version", conn, (const char*)data,
		                  len);
		return false;
		}

	if ( packet->is_orig )
		or_it->second.valid_orig = true;
	else
		or_it->second.valid_resp = true;

	Confirm(or_it->second.valid_orig, or_it->second.valid_resp);

	ValPtr teredo_hdr;

	if ( teredo_packet )
		{
		teredo_hdr = te.BuildVal(inner);
		packet->session->EnqueueEvent(teredo_packet, nullptr, packet->session->GetVal(),
		                              teredo_hdr);
		}

	if ( te.Authentication() && teredo_authentication )
		{
		if ( ! teredo_hdr )
			teredo_hdr = te.BuildVal(inner);

		packet->session->EnqueueEvent(teredo_authentication, nullptr, packet->session->GetVal(),
		                              teredo_hdr);
		}

	if ( te.OriginIndication() && teredo_origin_indication )
		{
		if ( ! teredo_hdr )
			teredo_hdr = te.BuildVal(inner);

		packet->session->EnqueueEvent(teredo_origin_indication, nullptr, packet->session->GetVal(),
		                              teredo_hdr);
		}

	if ( inner->NextProto() == IPPROTO_NONE && teredo_bubble )
		{
		if ( ! teredo_hdr )
			teredo_hdr = te.BuildVal(inner);

		packet->session->EnqueueEvent(teredo_bubble, nullptr, packet->session->GetVal(),
		                              teredo_hdr);
		}

	int encap_index = 0;
	auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(
		packet, &encap_index, nullptr, len, te.InnerIP(), DLT_RAW, BifEnum::Tunnel::TEREDO,
		GetAnalyzerTag());

	return ForwardPacket(len, te.InnerIP(), inner_packet.get());
	}

bool TeredoAnalyzer::DetectProtocol(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! BifConst::Tunnel::enable_teredo )
		return false;

	// Do some fast checks that must be true before moving to more complicated ones.
	// Mostly this avoids doing the regex below if we can help it.
	if ( (len < 40) || ((len > 8) && ((data[0] >> 4) != 6) &&
	                    ((data[0] != 0x00) || (data[1] != 0x00 && data[1] != 0x01))) )
		return false;

	if ( pattern_re->Match(data, len) )
		return true;

	uint16_t val = data[1];

	if ( val == 1 )
		{
		// If the second byte is 0x01, this is an authentication header. Grab
		// the length of the client identifier and the length of the
		// authentication block, and make sure that we have enough data to
		// include them with an IPv6 header.

		uint8_t client_id_length = data[2];
		uint8_t auth_length = data[3];

		if ( len < (static_cast<size_t>(13) + client_id_length + auth_length) )
			return false;

		// There's 9 bytes at the end of the header for a nonce value and a
		// confirmation byte. That plus the 4 bytes we've looked at already
		// makes 13 bytes.
		data += 13 + client_id_length + auth_length;
		len -= 13 + client_id_length + auth_length;

		if ( len < 40 )
			return false;

		// Get the next two octets after the authentication header, which
		// should be an origin identification header.
		val = htons(*(reinterpret_cast<const uint16_t*>(data)));
		}

	if ( val == 0 )
		{
		if ( len < 8 )
			return false;

		// If the second byte is zero (or we're coming out of an authentication
		// header), we're in an origin identification header. Skip over it, and
		// verify there's enough data after it to find an IPv6 header.
		data += 8;
		len -= 8;

		if ( len < 40 )
			return false;

		// Double check that the next byte in the header contains an IPv6
		// version number.
		val = data[0] >> 4;
		if ( val == 6 )
			return true;
		}

	return false;
	}

	} // namespace zeek::packet_analysis::teredo
