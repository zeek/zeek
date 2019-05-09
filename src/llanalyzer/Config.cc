// See the file "COPYING" in the main distribution directory for copyright.

#include "Config.h"
#include "Reporter.h"
#include "DebugLogger.h"

namespace zeek::llanalyzer {

// ##############################
// ####### DispatcherConfig #####
// ##############################
const std::string& DispatcherConfig::GetName() const
	{
	return name;
	}

const std::map<identifier_t, std::string>& DispatcherConfig::GetMappings() const
	{
	return mappings;
	}

void DispatcherConfig::AddMapping(identifier_t identifier,
								  const std::string& analyzer_name)
	{
	DBG_LOG(DBG_LLANALYZER, "Adding configuration mapping: %s -> %#x -> %s",
	        name.c_str(), identifier, analyzer_name.c_str());

	if ( mappings.count(identifier) )
		reporter->InternalError("Invalid config, identifier %#x already exists "
		                        "for dispatcher set %s.",
		                        identifier, name.c_str());

	mappings.emplace(identifier, analyzer_name);
	}

bool DispatcherConfig::operator==(const DispatcherConfig& rhs) const
	{
	return name == rhs.name;
	}

bool DispatcherConfig::operator!=(const DispatcherConfig& rhs) const
	{
	return ! (rhs == *this);
	}

// ##############################
// ########### Config ###########
// ##############################
std::optional<std::reference_wrapper<DispatcherConfig>>
Config::GetDispatcherConfig(const std::string& name)
	{
	auto it = std::find_if(
		dispatchers.begin(), dispatchers.end(),
		[&](const DispatcherConfig& conf) {
			return conf.GetName() == name;
			});

	if ( it == dispatchers.end() )
		return {};
	else
		return {std::ref(*it)};
	}

const std::vector<DispatcherConfig>& Config::GetDispatchers() const
	{
	return dispatchers;
	}

DispatcherConfig& Config::AddDispatcherConfig(const std::string& name)
	{
	return dispatchers.emplace_back(name);
	}

void Config::AddMapping(const std::string& name, identifier_t identifier,
						const std::string& analyzer_name)
	{
	// Create dispatcher config if it does not exist yet
	std::optional<std::reference_wrapper<DispatcherConfig>> dispatch_config =
		GetDispatcherConfig(name);

	if ( ! dispatch_config )
		AddDispatcherConfig(name).AddMapping(identifier, analyzer_name);
	else
		dispatch_config->get().AddMapping(identifier, analyzer_name);
	}

} // namespace llanalyzer
