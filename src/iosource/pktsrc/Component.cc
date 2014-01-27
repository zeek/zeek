// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"

#include "../Desc.h"

using namespace iosource::pktsrc;

SourceComponent::SourceComponent(const std::string& arg_name, const std::string& arg_prefix, InputType arg_type, factory_callback arg_factory)
	: iosource::Component(plugin::component::PKTSRC, arg_name)
	{
	prefix = arg_prefix;
	type = arg_type;
	factory = arg_factory;
	}

SourceComponent::~SourceComponent()
	{
	}

const std::string& SourceComponent::Prefix() const
	{
	return prefix;
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

	d->Add(" (interface prefix: ");
	d->Add(prefix);
	d->Add(")");
	}

DumperComponent::DumperComponent(const std::string& name, const std::string& arg_prefix, factory_callback arg_factory)
	: plugin::Component(plugin::component::PKTDUMPER, name)
	{
	factory = arg_factory;
	prefix = arg_prefix;
	}

DumperComponent::~DumperComponent()
	{
	}

DumperComponent::factory_callback DumperComponent::Factory() const
	{
	return factory;
	}

const std::string& DumperComponent::Prefix() const
	{
	return prefix;
	}

void DumperComponent::Describe(ODesc* d) const
	{
	plugin::Component::Describe(d);

	d->Add(" (dumper prefix: ");
	d->Add(prefix);
	d->Add(")");
	}

