// See the file in the main distribution directory for copyright.

#pragma once

#include <mutex>

#include "plugin/Plugin.h"

#include "Raw.h"

namespace zeek::plugin::Zeek_RawReader {

class Plugin : public zeek::plugin::Plugin {
public:
	Plugin();

	zeek::plugin::Configuration Configure() override;

	void InitPreScript() override;
	void Done() override;

	std::unique_lock<std::mutex> ForkMutex();

private:
	std::mutex fork_mutex;

};

extern Plugin plugin;

} // namespace zeek::plugin::Zeek_RawReader
