// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"

#include "../Desc.h"
#include "../Reporter.h"

using namespace iosource::pktsrc;

SourceComponent::SourceComponent(const std::string& arg_name, const std::string& arg_prefix, InputType arg_type, factory_callback arg_factory)
	: iosource::Component(plugin::component::PKTSRC, arg_name)
	{
	tokenize_string(arg_prefix, ":", &prefixes);
	type = arg_type;
	factory = arg_factory;
	}

SourceComponent::~SourceComponent()
	{
	}

const std::vector<std::string>& SourceComponent::Prefixes() const
	{
	return prefixes;
	}

bool SourceComponent::HandlesPrefix(const string& prefix) const
	{
	for ( std::vector<std::string>::const_iterator i = prefixes.begin();
	      i != prefixes.end(); i++ )
		{
		if ( *i == prefix )
			return true;
		}

	return false;
	}

bool SourceComponent::DoesLive() const
	{
	return type == LIVE || type == BOTH;
	}

bool SourceComponent::DoesTrace() const
	{
	return type == TRACE || type == BOTH;
	}

SourceComponent::factory_callback SourceComponent::Factory() const
	{
	return factory;
	}


void SourceComponent::Describe(ODesc* d) const
	{
	iosource::Component::Describe(d);

	string prefs;

	for ( std::vector<std::string>::const_iterator i = prefixes.begin();
	      i != prefixes.end(); i++ )
		{
		if ( prefs.size() )
			prefs += ", ";

		prefs += *i;
		}

	d->Add(" (interface prefix");
	if ( prefixes.size() > 1 )
		d->Add("es");

	d->Add(": ");
	d->Add(prefs);
	d->Add("; ");

	switch ( type ) {
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

	d->Add(")");
	}

DumperComponent::DumperComponent(const std::string& name, const std::string& arg_prefix, factory_callback arg_factory)
	: plugin::Component(plugin::component::PKTDUMPER, name)
	{
	tokenize_string(arg_prefix, ":", &prefixes);
	factory = arg_factory;
	}

DumperComponent::~DumperComponent()
	{
	}

DumperComponent::factory_callback DumperComponent::Factory() const
	{
	return factory;
	}

const std::vector<std::string>& DumperComponent::Prefixes() const
	{
	return prefixes;
	}

bool DumperComponent::HandlesPrefix(const string& prefix) const
	{
	for ( std::vector<std::string>::const_iterator i = prefixes.begin();
	      i != prefixes.end(); i++ )
		{
		if ( *i == prefix )
			return true;
		}

	return false;
	}

void DumperComponent::Describe(ODesc* d) const
	{
	plugin::Component::Describe(d);

	string prefs;

	for ( std::vector<std::string>::const_iterator i = prefixes.begin();
	      i != prefixes.end(); i++ )
		{
		if ( prefs.size() )
			prefs += ", ";

		prefs += *i;
		}

	d->Add(" (dumper prefix");

	if ( prefixes.size() > 1 )
		d->Add("es");

	d->Add(": ");
	d->Add(prefs);
	d->Add(")");
	}

