
#include <fcntl.h>
#include <stdio.h>

#include "Foo.h"

using namespace plugin::Demo_Foo;

Foo::Foo(const std::string& path, bool is_live)
	{
	packet =
	string("\x45\x00\x00\x40\x15\x55\x40\x00\x3e\x06\x25\x5b\x01\x02\x00\x02"
	"\x01\x02\x00\x03\x09\xdf\x19\xf9\x5d\x8a\x36\x7c\x00\x00\x00\x00"
	"\xb0\x02\x40\x00\x3c\x72\x00\x00\x02\x04\x05\x5c\x01\x03\x03\x00"
	"\x01\x01\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x04\x02", 64);

	props.path = path;
	props.selectable_fd = open("/bin/sh", O_RDONLY); // any fd is fine.
	props.link_type = DLT_RAW;
	props.netmask = 0;
	props.is_live = 0;
	}

iosource::PktSrc* Foo::Instantiate(const std::string& path, bool is_live)
	{
	return new Foo(path, is_live);
	}

void Foo::Open()
	{
	Opened(props);
	}

void Foo::Close()
	{
	Closed();
	}

bool Foo::ExtractNextPacket(Packet* pkt)
	{
	if ( packet.empty() )
		{
		Close();
		return false;
		}

	struct timeval ts = { 1409193037, 0 };
	pkt->Init(props.link_type, &ts, packet.size(), packet.size(), 
		(const u_char *)packet.c_str());
	return true;
	}

void Foo::DoneWithPacket()
	{
	packet.clear();
	}

bool Foo::PrecompileFilter(int index, const std::string& filter)
	{
	// skip for the testing.
	return true;
	}

bool Foo::SetFilter(int index)
	{
	// skip for the testing.
	return true;
	}

void Foo::Statistics(Stats* stats)
	{
	// skip for the testing.
	}
