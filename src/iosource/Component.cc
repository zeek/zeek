
#include "Component.h"

#include "Desc.h"

using namespace iosource;

Component::Component(const std::string& name)
	: plugin::Component(plugin::component::IOSOURCE, name)
	{
	}

Component::Component(plugin::component::Type type, const std::string& name)
	: plugin::Component(type, name)
	{
	}

Component::~Component()
	{
	}
