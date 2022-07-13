
#pragma once

#include <Val.h>
#include <iosource/PktSrc.h>

namespace btest::plugin::Demo_Foo
	{

class Foo : public zeek::iosource::PktSrc
	{
public:
	Foo(const std::string& path, bool is_live);

	static zeek::iosource::PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	virtual void Open();
	virtual void Close();
	virtual bool ExtractNextPacket(zeek::Packet* pkt);
	virtual void DoneWithPacket();
	virtual bool PrecompileFilter(int index, const std::string& filter);
	virtual bool SetFilter(int index);
	virtual void Statistics(Stats* stats);

private:
	Properties props;
	std::string packet;
	};

	}
