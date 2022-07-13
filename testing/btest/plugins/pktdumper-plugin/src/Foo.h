#pragma once

#include <Val.h>
#include <iosource/PktDumper.h>

namespace btest::plugin::Demo_Foo
	{

class Foo : public zeek::iosource::PktDumper
	{
public:
	Foo(const std::string& path, bool is_live);
	virtual ~Foo();

	static zeek::iosource::PktDumper* Instantiate(const std::string& path, bool append);

protected:
	virtual void Open();
	virtual void Close();
	virtual bool Dump(const zeek::Packet* pkt);

private:
	Properties props;
	};

	}
