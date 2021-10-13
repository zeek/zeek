#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

#include "zeek/File.h"
#include "zeek/ZeekString.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

using namespace zeek::packet_analysis::IP;

void SessionAdapter::Done()
	{
	Analyzer::Done();
	}

bool SessionAdapter::IsReuse(double t, const u_char* pkt)
	{
	return parent->IsReuse(t, pkt);
	}

void SessionAdapter::SetContentsFile(unsigned int /* direction */, FilePtr /* f */)
	{
	reporter->Error("analyzer type does not support writing to a contents file");
	}

zeek::FilePtr SessionAdapter::GetContentsFile(unsigned int /* direction */) const
	{
	reporter->Error("analyzer type does not support writing to a contents file");
	return nullptr;
	}

void SessionAdapter::PacketContents(const u_char* data, int len)
	{
	if ( packet_contents && len > 0 )
		{
		zeek::String* cbs = new zeek::String(data, len, true);
		auto contents = make_intrusive<StringVal>(cbs);
		EnqueueConnEvent(packet_contents, ConnVal(), std::move(contents));
		}
	}
