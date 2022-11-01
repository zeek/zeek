
#include "Plugin.h"

#include <mutex>

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/RunState.h"
#include "zeek/threading/Formatter.h"

#include "statistics.bif.h"

namespace zeek::plugin::statistics
	{
Plugin plugin;
	}

using namespace zeek::plugin::statistics;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Statistics";
	config.description = "Statistics module";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

bool Plugin::HookQueueEvent(zeek::Event* event)
	{
	const char* name = event->Handler()->Name();

	std::lock_guard<std::mutex> scopedLock(m_lock);
	if ( m_eventNameCounters.find(name) == m_eventNameCounters.end() )
		{
		m_eventNameCounters[name] = 0;
		}
	m_eventNameCounters[name]++;
	return false;
	}

std::unordered_map<const char*, int> Plugin::GetAndResetEventStatistics()
	{
	std::lock_guard<std::mutex> scopedLock(m_lock);
	std::unordered_map<const char*, int> result(m_eventNameCounters);
	m_eventNameCounters.clear();
	return result;
	}

void Plugin::StartEventNamesStatisticsMonitor()
	{
	EnableHook(zeek::plugin::HOOK_QUEUE_EVENT);
	}
