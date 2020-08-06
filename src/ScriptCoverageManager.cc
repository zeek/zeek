#include "ScriptCoverageManager.h"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <fstream>
#include <utility>
#include <algorithm>
#include <sys/stat.h>

#include "Stmt.h"
#include "Desc.h"
#include "Reporter.h"
#include "util.h"

using namespace std;

namespace zeek::detail {

ScriptCoverageManager::ScriptCoverageManager()
	: ignoring(0), delim('\t')
	{
	}

ScriptCoverageManager::~ScriptCoverageManager()
	{
	for ( auto& s : stmts )
		Unref(s);
	}

void ScriptCoverageManager::AddStmt(zeek::detail::Stmt* s)
	{
	if ( ignoring != 0 )
		return;

	zeek::Ref(s);
	stmts.push_back(s);
	}

bool ScriptCoverageManager::ReadStats()
	{
	char* bf = zeek::util::zeekenv("ZEEK_PROFILER_FILE");

	if ( ! bf )
		return false;

	std::ifstream ifs;
	ifs.open(bf, std::ifstream::in);

	if ( ! ifs )
		return false;

	std::stringstream ss;
	ss << ifs.rdbuf();
	std::string file_contents = ss.str();
	ss.clear();

	std::vector<std::string> lines;
	zeek::util::tokenize_string(file_contents, "\n", &lines);
	string delimiter;
	delimiter = delim;

	for ( const auto& line : lines )
		{
		if ( line.empty() )
			continue;

		std::vector<std::string> line_components;
		zeek::util::tokenize_string(line, delimiter, &line_components);

		if ( line_components.size() != 3 )
			{
			fprintf(stderr, "invalid ZEEK_PROFILER_FILE line: %s\n", line.data());
			continue;
			}

		std::string& cnt = line_components[0];
		std::string& location = line_components[1];
		std::string& desc = line_components[2];

		pair<string, string> location_desc(std::move(location), std::move(desc));
		uint64_t count;
		zeek::util::atoi_n(cnt.size(), cnt.c_str(), nullptr, 10, count);
		usage_map.emplace(std::move(location_desc), count);
		}

	return true;
	}

bool ScriptCoverageManager::WriteStats()
	{
	char* bf = zeek::util::zeekenv("ZEEK_PROFILER_FILE");

	if ( ! bf )
		return false;

	zeek::util::SafeDirname dirname{bf};

	if ( ! zeek::util::ensure_intermediate_dirs(dirname.result.data()) )
		{
		zeek::reporter->Error("Failed to open ZEEK_PROFILER_FILE destination '%s' for writing", bf);
		return false;
		}

	FILE* f;
	const char* p = strstr(bf, "XXXXXX");

	if ( p && ! p[6] )
		{
		mode_t old_umask = umask(S_IXUSR | S_IRWXO | S_IRWXG);
		int fd = mkstemp(bf);
		umask(old_umask);

		if ( fd == -1 )
			{
			zeek::reporter->Error("Failed to generate unique file name from ZEEK_PROFILER_FILE: %s", bf);
			return false;
			}
		f = fdopen(fd, "w");
		}
	else
		{
		f = fopen(bf, "w");
		}

	if ( ! f )
		{
		zeek::reporter->Error("Failed to open ZEEK_PROFILER_FILE destination '%s' for writing", bf);
		return false;
		}

	for ( list<zeek::detail::Stmt*>::const_iterator it = stmts.begin();
	      it != stmts.end(); ++it )
		{
		ODesc location_info;
		(*it)->GetLocationInfo()->Describe(&location_info);
		ODesc desc_info;
		(*it)->Describe(&desc_info);
		string desc(desc_info.Description());
		canonicalize_desc cd{delim};
		for_each(desc.begin(), desc.end(), cd);
		pair<string, string> location_desc(location_info.Description(), desc);
		if ( usage_map.find(location_desc) != usage_map.end() )
			usage_map[location_desc] += (*it)->GetAccessCount();
		else
			usage_map[location_desc] = (*it)->GetAccessCount();
		}

	map<pair<string, string>, uint64_t >::const_iterator it;
	for ( it = usage_map.begin(); it != usage_map.end(); ++it )
		{
		fprintf(f, "%" PRIu64"%c%s%c%s\n", it->second, delim,
				it->first.first.c_str(), delim, it->first.second.c_str());
		}

	fclose(f);
	return true;
	}

} // namespace zeek::detail
