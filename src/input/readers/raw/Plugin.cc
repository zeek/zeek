// See the file  in the main distribution directory for copyright.

#include "Plugin.h"

namespace zeek::plugin::Zeek_RawReader {

Plugin plugin;

Plugin::Plugin()
	{
	}

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::input::Component("Raw", zeek::input::reader::detail::Raw::Instantiate));

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

} // namespace zeek::plugin::Zeek_RawReader
