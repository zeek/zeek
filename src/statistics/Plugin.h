
#pragma once

#include <unordered_map>
#include <mutex>
#include <string>
#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::statistics {

class Plugin : public zeek::plugin::Plugin
{
protected:
	bool HookQueueEvent(zeek::Event* event) override;

	zeek::plugin::Configuration Configure() override;

public:
	std::unordered_map<const char*, int> GetAndResetEventStatistics();
	void StartEventNamesStatisticsMonitor();
	
private:
	std::unordered_map<const char*, int> m_eventNameCounters;
	std::mutex m_lock;

};

extern Plugin plugin;
}
