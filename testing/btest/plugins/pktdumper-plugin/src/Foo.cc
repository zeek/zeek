
#include <fcntl.h>
#include <stdio.h>

#include "Foo.h"

using namespace plugin::Demo_Foo;

Foo::Foo(const std::string& path, bool is_live)
	{
	props.path = path;
	}

Foo::~Foo()
	{
	}

void Foo::Open()
	{
	props.open_time = network_time;
	props.hdr_size = 0;
	Opened(props);
	}

void Foo::Close()
	{
	Closed();
	}

bool Foo::Dump(const Packet* pkt)
	{
	double t = double(pkt->ts.tv_sec) + double(pkt->ts.tv_usec) / 1e6;
	fprintf(stdout, "Dumping to %s: %.6f len %u\n", props.path.c_str(), t, (unsigned int)pkt->len);
	return true;
	}

iosource::PktDumper* Foo::Instantiate(const std::string& path, bool append)
	{
	return new Foo(path, append);
	}
