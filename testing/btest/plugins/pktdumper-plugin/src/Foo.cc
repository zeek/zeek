
#include "Foo.h"

#include <fcntl.h>
#include <cstdio>

#include "RunState.h"
#include "iosource/Packet.h"

using namespace btest::plugin::Demo_Foo;

Foo::Foo(const std::string& path, bool is_live)
	{
	props.path = path;
	}

Foo::~Foo() { }

void Foo::Open()
	{
	props.open_time = zeek::run_state::network_time;
	Opened(props);
	}

void Foo::Close()
	{
	Closed();
	}

bool Foo::Dump(const zeek::Packet* pkt)
	{
	double t = double(pkt->ts.tv_sec) + double(pkt->ts.tv_usec) / 1e6;
	fprintf(stdout, "Dumping to %s: %.6f len %u\n", props.path.c_str(), t, (unsigned int)pkt->len);
	return true;
	}

zeek::iosource::PktDumper* Foo::Instantiate(const std::string& path, bool append)
	{
	return new Foo(path, append);
	}
