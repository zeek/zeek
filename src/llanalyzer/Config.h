// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "Defines.h"

namespace zeek::llanalyzer {

class DispatcherConfig {
public:
	explicit DispatcherConfig(const std::string name) : name(std::move(name)) { }

	const std::string& GetName() const;
	const std::map<identifier_t, std::string>& GetMappings() const;

	void AddMapping(identifier_t identifier, const std::string& analyzer_name);

	bool operator==(const DispatcherConfig& rhs) const;
	bool operator!=(const DispatcherConfig& rhs) const;

private:
	const std::string name;
	std::map<identifier_t, std::string> mappings;
};

class Config {

public:
	const std::vector<DispatcherConfig>& GetDispatchers() const;
	std::optional<std::reference_wrapper<DispatcherConfig>> GetDispatcherConfig(const std::string& name);
	DispatcherConfig& AddDispatcherConfig(const std::string& name);
	void AddMapping(const std::string& name, identifier_t identifier, const std::string& analyzer_name);

private:
	std::vector<DispatcherConfig> dispatchers;
};

}
