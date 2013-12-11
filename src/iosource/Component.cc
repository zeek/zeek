
#include "Component.h"

#include "Desc.h"

using namespace iosource;

Component::Component(const std::string& arg_name)
	: plugin::Component(plugin::component::IOSOURCE)
	{
	name = arg_name;
	}

Component::Component(plugin::component::Type type, const std::string& arg_name)
	: plugin::Component(type)
	{
	name = arg_name;
	}

Component::Component(const Component& other)
	: plugin::Component(other)
	{
	name = other.name;
	}

Component::~Component()
	{
	}

void Component::Describe(ODesc* d) const
	{
	plugin::Component::Describe(d);
	d->Add(name);
	}

Component& Component::operator=(const Component& other)
	{
	plugin::Component::operator=(other);

	if ( &other != this )
		name = other.name;

	return *this;
	}
