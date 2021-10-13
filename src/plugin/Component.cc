// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Component.h"

#include "zeek/Desc.h"
#include "zeek/Reporter.h"

namespace zeek::plugin
	{

Component::Component(component::Type arg_type, const std::string& arg_name)
	{
	type = arg_type;
	name = arg_name;
	canon_name = util::canonify_name(name);
	}

Component::~Component() { }

const std::string& Component::Name() const
	{
	return name;
	}

component::Type Component::Type() const
	{
	return type;
	}

void Component::Describe(ODesc* d) const
	{
	d->Add("    ");
	d->Add("[");

	switch ( type )
		{
		case component::READER:
			d->Add("Reader");
			break;

		case component::WRITER:
			d->Add("Writer");
			break;

		case component::ANALYZER:
			d->Add("Analyzer");
			break;

		case component::PACKET_ANALYZER:
			d->Add("Packet Analyzer");
			break;

		case component::FILE_ANALYZER:
			d->Add("File Analyzer");
			break;

		case component::IOSOURCE:
			d->Add("I/O Source");
			break;

		case component::PKTSRC:
			d->Add("Packet Source");
			break;

		case component::PKTDUMPER:
			d->Add("Packet Dumper");
			break;

		case component::SESSION_ADAPTER:
			d->Add("Session Adapter");
			break;

		default:
			reporter->InternalWarning("unknown component type in plugin::Component::Describe");
			d->Add("<unknown component type>");
			break;
		}

	d->Add("]");
	d->Add(" ");
	d->Add(name);
	d->Add(" (");
	DoDescribe(d);
	d->Add(")");
	}

	} // namespace zeek::plugin
