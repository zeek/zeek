// See the file  in the main distribution directory for copyright.

#include "Plugin.h"

namespace plugin { namespace Bro_RawReader { Plugin plugin; } }

using namespace plugin::Bro_RawReader;

Plugin::Plugin()
	{
	init = false;
	}

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::input::Component("Raw", ::input::reader::Raw::Instantiate));

	plugin::Configuration config;
	config.name = "Bro::RawReader";
	config.description = "Raw input reader";
	return config;
	}

void Plugin::InitPreScript()
	{
	if ( pthread_mutex_init(&fork_mutex, 0) != 0 )
		reporter->FatalError("cannot initialize raw reader's mutex");

	init = true;
	}

void Plugin::Done()
	{
	pthread_mutex_destroy(&fork_mutex);
	init = false;
	}

pthread_mutex_t* Plugin::ForkMutex()
	{
	assert(init);
	return &fork_mutex;
	}

