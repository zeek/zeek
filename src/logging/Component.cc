// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"
#include "../Desc.h"
#include "../util.h"

using namespace logging;

Component::Component(const std::string& name, factory_callback arg_factory)
	: plugin::Component(plugin::component::WRITER, name)
	{
	factory = arg_factory;

	log_mgr->RegisterComponent(this, "WRITER_");
	}

Component::~Component()
	{
	}

void Component::DoDescribe(ODesc* d) const
	{
	d->Add("Log::WRITER_");
	d->Add(CanonicalName());
	}
