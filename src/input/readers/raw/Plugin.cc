// See the file  in the main distribution directory for copyright.

#include "Plugin.h"

namespace plugin { namespace Zeek_RawReader { Plugin plugin; } }

using namespace plugin::Zeek_RawReader;

Plugin::Plugin()
	{
	}

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::input::Component("Raw", ::input::reader::Raw::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Zeek::RawReader";
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
