#include "zeek/ScriptCoverageManager.h"

#include <sys/stat.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"

using namespace std;

namespace zeek::detail
	{

ScriptCoverageManager::ScriptCoverageManager() : ignoring(0), delim('\t') { }

void ScriptCoverageManager::AddStmt(Stmt* s)
	{
	if ( ignoring != 0 )
		return;

	stmts.push_back({NewRef{}, s});
	}

void ScriptCoverageManager::AddFunction(IDPtr func_id, StmtPtr body)
	{
	func_instances.push_back({func_id, body});
	}

bool ScriptCoverageManager::ReadStats()
	{
	char* bf = getenv("ZEEK_PROFILER_FILE");

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
	util::tokenize_string(file_contents, "\n", &lines);
	string delimiter;
	delimiter = delim;

	for ( const auto& line : lines )
		{
		if ( line.empty() )
			continue;

		std::vector<std::string> line_components;
		util::tokenize_string(line, delimiter, &line_components);

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
		util::atoi_n(cnt.size(), cnt.c_str(), nullptr, 10, count);
		usage_map.emplace(std::move(location_desc), count);
		}

	return true;
	}

bool ScriptCoverageManager::WriteStats()
	{
	char* bf = getenv("ZEEK_PROFILER_FILE");

	if ( ! bf )
		return false;

	util::SafeDirname dirname{bf};

	if ( ! util::detail::ensure_intermediate_dirs(dirname.result.data()) )
		{
		reporter->Error("Failed to open ZEEK_PROFILER_FILE destination '%s' for writing", bf);
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
			reporter->Error("Failed to generate unique file name from ZEEK_PROFILER_FILE: %s", bf);
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
		reporter->Error("Failed to open ZEEK_PROFILER_FILE destination '%s' for writing", bf);
		return false;
		}

	for ( auto& s : stmts )
		{
		ODesc desc_info;
		s->Describe(&desc_info);
		TrackUsage(s, desc_info.Description(), s->GetAccessCount());
		}

	for ( auto& [func, body] : func_instances )
		{
		auto ft = func->GetType<FuncType>();
		auto desc = ft->FlavorString() + " " + func->Name() + " BODY";

		TrackUsage(body, desc, body->GetAccessCount());
		}

	for ( auto& [location_info, cnt] : usage_map )
		Report(f, cnt, location_info.first, location_info.second);

	fclose(f);
	return true;
	}

void ScriptCoverageManager::TrackUsage(const ObjPtr& obj, std::string desc, uint64_t cnt)
	{
	ODesc location_info;
	obj->GetLocationInfo()->Describe(&location_info);

	static canonicalize_desc cd{delim};
	for_each(desc.begin(), desc.end(), cd);

	pair<string, string> location_desc(location_info.Description(), desc);

	if ( usage_map.find(location_desc) != usage_map.end() )
		usage_map[location_desc] += cnt;
	else
		usage_map[location_desc] = cnt;
	}

void ScriptCoverageManager::Report(FILE* f, uint64_t cnt, std::string loc, std::string desc)
	{
	fprintf(f, "%" PRIu64 "%c%s%c%s\n", cnt, delim, loc.c_str(), delim, desc.c_str());
	}

	} // namespace zeek::detail
