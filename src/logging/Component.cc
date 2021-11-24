// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/logging/Component.h"

#include "zeek/Desc.h"
#include "zeek/logging/Manager.h"
#include "zeek/util.h"

namespace zeek::logging
	{

Component::Component(const std::string& name, factory_callback arg_factory)
	: plugin::Component(plugin::component::WRITER, name, 0, log_mgr->GetTagType())
	{
	factory = arg_factory;
	}

void Component::Initialize()
	{
	InitializeTag();
	log_mgr->RegisterComponent(this, "WRITER_");
	}

Component::~Component() { }

void Component::DoDescribe(ODesc* d) const
	{
	d->Add("Log::WRITER_");
	d->Add(CanonicalName());
	}

	} // namespace zeek::logging
