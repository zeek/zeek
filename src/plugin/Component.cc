// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Component.h"

#include "zeek/Desc.h"
#include "zeek/Reporter.h"

namespace zeek::plugin
	{

Tag::type_t Component::type_counter(0);

Component::Component(component::Type arg_type, const std::string& arg_name,
                     Tag::subtype_t tag_subtype, EnumTypePtr etype)
	: type(arg_type), name(arg_name), tag(etype, 1, 0), etype(std::move(etype)),
	  tag_subtype(tag_subtype)
	{
	canon_name = util::canonify_name(name);
	canon_name_val = make_intrusive<StringVal>(canon_name);
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

void Component::InitializeTag()
	{
	assert(tag_initialized == false);
	tag_initialized = true;
	tag = zeek::Tag(etype, ++type_counter, tag_subtype);
	}

/**
 * @return The component's tag.
 */
zeek::Tag Component::Tag() const
	{
	assert(tag_initialized);
	return tag;
	}

	} // namespace zeek::plugin
