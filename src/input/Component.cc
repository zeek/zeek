// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"

#include "../Desc.h"
#include "../util.h"

using namespace input;

Component::Component(const std::string& name, factory_callback arg_factory)
	: plugin::Component(plugin::component::READER, name)
	{
	factory = arg_factory;

	input_mgr->RegisterComponent(this, "READER_");
	}

Component::~Component()
	{
	}

void Component::DoDescribe(ODesc* d) const
	{
	d->Add("Input::READER_");
	d->Add(CanonicalName());
	}

