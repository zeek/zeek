#include <cstdio>
#include <cstring>
#include <utility>
#include <algorithm>
#include <sys/stat.h>
#include "Brofiler.h"
#include "util.h"

Brofiler::Brofiler()
	: ignoring(0), delim('\t')
	{
	}

Brofiler::~Brofiler()
	{
	}

bool Brofiler::ReadStats()
	{
	char* bf = getenv("BRO_PROFILER_FILE");
	if ( ! bf )
		return false;

	FILE* f = fopen(bf, "r");
	if ( ! f )
		return false;

	char line[16384];
	string delimiter;
	delimiter = delim;

	while( fgets(line, sizeof(line), f) )
		{
		line[strlen(line) - 1] = 0; //remove newline
		string cnt(strtok(line, delimiter.c_str()));
		string location(strtok(0, delimiter.c_str()));
		string desc(strtok(0, delimiter.c_str()));
		pair<string, string> location_desc(location, desc);
		uint64 count;
		atoi_n(cnt.size(), cnt.c_str(), 0, 10, count);
		usage_map[location_desc] = count;
		}

	fclose(f);
	return true;
	}

bool Brofiler::WriteStats()
	{
	char* bf = getenv("BRO_PROFILER_FILE");
	if ( ! bf ) return false;

	FILE* f;
	const char* p = strstr(bf, ".XXXXXX");

	if ( p && ! p[7] )
		{
		mode_t old_umask = umask(S_IXUSR | S_IRWXO | S_IRWXG);
		int fd = mkstemp(bf);
		umask(old_umask);

		if ( fd == -1 )
			{
			reporter->Error("Failed to generate unique file name from BRO_PROFILER_FILE: %s", bf);
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
		reporter->Error("Failed to open BRO_PROFILER_FILE destination '%s' for writing", bf);
		return false;
		}

	for ( list<const Stmt*>::const_iterator it = stmts.begin();
	      it != stmts.end(); ++it )
		{
		ODesc location_info;
		(*it)->GetLocationInfo()->Describe(&location_info);
		ODesc desc_info;
		(*it)->Describe(&desc_info);
		string desc(desc_info.Description());
		for_each(desc.begin(), desc.end(), canonicalize_desc());
		pair<string, string> location_desc(location_info.Description(), desc);
		if ( usage_map.find(location_desc) != usage_map.end() )
			usage_map[location_desc] += (*it)->GetAccessCount();
		else
			usage_map[location_desc] = (*it)->GetAccessCount();
		}

	map<pair<string, string>, uint64 >::const_iterator it;
	for ( it = usage_map.begin(); it != usage_map.end(); ++it )
		{
		fprintf(f, "%"PRIu64"%c%s%c%s\n", it->second, delim,
				it->first.first.c_str(), delim, it->first.second.c_str());
		}

	fclose(f);
	return true;
	}

