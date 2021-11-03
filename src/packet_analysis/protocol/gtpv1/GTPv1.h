#pragma once

#include "zeek/packet_analysis/Analyzer.h"

#include "packet_analysis/protocol/gtpv1/gtpv1_pac.h"

namespace binpac::GTPv1
	{
class GTPv1_Conn;
	}

namespace zeek::packet_analysis::gtpv1
	{

class GTPv1_Analyzer final : public packet_analysis::Analyzer
	{
public:
	explicit GTPv1_Analyzer();
	~GTPv1_Analyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<GTPv1_Analyzer>();
		}

	void SetInnerInfo(int offset, uint8_t next, RecordValPtr val)
		{
		inner_packet_offset = offset;
		next_header = next;
		gtp_hdr_val = std::move(val);
		}

	void RemoveConnection(const zeek::detail::ConnKey& conn_key) { conn_map.erase(conn_key); }

protected:
	using ConnMap = std::map<zeek::detail::ConnKey, std::unique_ptr<binpac::GTPv1::GTPv1_Conn>>;
	ConnMap conn_map;

	int inner_packet_offset = -1;
	uint8_t next_header = 0;
	RecordValPtr gtp_hdr_val;
	};

	} // namespace zeek::packet_analysis::gtpv1
