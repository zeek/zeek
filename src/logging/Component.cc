// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"
#include "../Desc.h"
#include "../util.h"

namespace zeek::logging {

Component::Component(const std::string& name, factory_callback arg_factory)
	: zeek::plugin::Component(zeek::plugin::component::WRITER, name)
	{
	factory = arg_factory;
	}

void Component::Initialize()
	{
	InitializeTag();
	log_mgr->RegisterComponent(this, "WRITER_");
	}

Component::~Component()
	{
	}

void Component::DoDescribe(zeek::ODesc* d) const
	{
	d->Add("Log::WRITER_");
	d->Add(CanonicalName());
	}

} // namespace zeek::logging
