// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/Component.h"

#include "zeek/Desc.h"
#include "zeek/Reporter.h"

namespace zeek::iosource
	{

Component::Component(const std::string& name) : plugin::Component(plugin::component::IOSOURCE, name)
	{
	}

Component::Component(plugin::component::Type type, const std::string& name)
	: plugin::Component(type, name)
	{
	}

Component::~Component() { }

PktSrcComponent::PktSrcComponent(const std::string& arg_name, const std::string& arg_prefix,
                                 InputType arg_type, factory_callback arg_factory)
	: Component(plugin::component::PKTSRC, arg_name)
	{
	util::tokenize_string(arg_prefix, ":", &prefixes);
	type = arg_type;
	factory = arg_factory;
	}

PktSrcComponent::~PktSrcComponent() { }

const std::vector<std::string>& PktSrcComponent::Prefixes() const
	{
	return prefixes;
	}

bool PktSrcComponent::HandlesPrefix(const std::string& prefix) const
	{
	for ( std::vector<std::string>::const_iterator i = prefixes.begin(); i != prefixes.end(); i++ )
		{
		if ( *i == prefix )
			return true;
		}

	return false;
	}

bool PktSrcComponent::DoesLive() const
	{
	return type == LIVE || type == BOTH;
	}

bool PktSrcComponent::DoesTrace() const
	{
	return type == TRACE || type == BOTH;
	}

PktSrcComponent::factory_callback PktSrcComponent::Factory() const
	{
	return factory;
	}

void PktSrcComponent::DoDescribe(ODesc* d) const
	{
	Component::DoDescribe(d);

	std::string prefs;

	for ( std::vector<std::string>::const_iterator i = prefixes.begin(); i != prefixes.end(); i++ )
		{
		if ( prefs.size() )
			prefs += ", ";

		prefs += '"' + *i + '"';
		}

	d->Add("interface prefix");
	if ( prefixes.size() > 1 )
		d->Add("es");

	d->Add(" ");
	d->Add(prefs);
	d->Add("; supports ");

	switch ( type )
		{
		case LIVE:
			d->Add("live input");
			break;

		case TRACE:
			d->Add("trace input");
			break;

		case BOTH:
			d->Add("live and trace input");
			break;

		default:
			reporter->InternalError("unknown PkrSrc type");
		}
	}

PktDumperComponent::PktDumperComponent(const std::string& name, const std::string& arg_prefix,
                                       factory_callback arg_factory)
	: plugin::Component(plugin::component::PKTDUMPER, name)
	{
	util::tokenize_string(arg_prefix, ":", &prefixes);
	factory = arg_factory;
	}

PktDumperComponent::~PktDumperComponent() { }

PktDumperComponent::factory_callback PktDumperComponent::Factory() const
	{
	return factory;
	}

const std::vector<std::string>& PktDumperComponent::Prefixes() const
	{
	return prefixes;
	}

bool PktDumperComponent::HandlesPrefix(const std::string& prefix) const
	{
	for ( std::vector<std::string>::const_iterator i = prefixes.begin(); i != prefixes.end(); i++ )
		{
		if ( *i == prefix )
			return true;
		}

	return false;
	}

void PktDumperComponent::DoDescribe(ODesc* d) const
	{
	plugin::Component::DoDescribe(d);

	std::string prefs;

	for ( std::vector<std::string>::const_iterator i = prefixes.begin(); i != prefixes.end(); i++ )
		{
		if ( prefs.size() )
			prefs += ", ";

		prefs += '"' + *i + '"';
		}

	d->Add("dumper prefix");

	if ( prefixes.size() > 1 )
		d->Add("es");

	d->Add(": ");
	d->Add(prefs);
	}

	} // namespace zeek::iosource
