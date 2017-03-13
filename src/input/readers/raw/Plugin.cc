// See the file  in the main distribution directory for copyright.

#include "Plugin.h"

namespace plugin { namespace Bro_RawReader { Plugin plugin; } }

using namespace plugin::Bro_RawReader;

Plugin::Plugin()
	{
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
	}

void Plugin::Done()
	{
	}

std::unique_lock<std::mutex> Plugin::ForkMutex()
	{
	return std::unique_lock<std::mutex>(fork_mutex, std::defer_lock);
	}

