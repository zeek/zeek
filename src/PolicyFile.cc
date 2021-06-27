#include "zeek/PolicyFile.h"

#include "zeek/zeek-config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "zeek/Debug.h"
#include "zeek/Reporter.h"
#include "zeek/util.h"

using namespace std;

struct PolicyFile
	{
	PolicyFile()
		{
		filedata = nullptr;
		lmtime = 0;
		}
	~PolicyFile()
		{
		delete[] filedata;
		filedata = nullptr;
		}

	time_t lmtime;
	char* filedata;
	vector<const char*> lines;
	};

using PolicyFileMap = map<string, PolicyFile*>;
static PolicyFileMap policy_files;

namespace zeek::detail
	{

int how_many_lines_in(const char* policy_filename)
	{
	if ( ! policy_filename )
		reporter->InternalError("NULL value passed to how_many_lines_in\n");

	FILE* throwaway = fopen(policy_filename, "r");
	if ( ! throwaway )
		{
		debug_msg("Could not open policy file: %s.\n", policy_filename);
		return -1;
		}

	fclose(throwaway);

	PolicyFileMap::iterator match;
	match = policy_files.find(policy_filename);

	if ( match == policy_files.end() )
		{
		match = policy_files.find(policy_filename);
		if ( match == policy_files.end() )
			{
			debug_msg("Policy file %s was not loaded.\n", policy_filename);
			return -1;
			}
		}

	PolicyFile* pf = match->second;
	return pf->lines.size();
	}

bool LoadPolicyFileText(const char* policy_filename,
                        const std::optional<std::string>& preloaded_content)
	{
	if ( ! policy_filename )
		return true;

	if ( policy_files.find(policy_filename) != policy_files.end() )
		debug_msg("Policy file %s already loaded\n", policy_filename);

	PolicyFile* pf = new PolicyFile;
	policy_files.insert(PolicyFileMap::value_type(policy_filename, pf));

	if ( preloaded_content )
		{
		auto size = preloaded_content->size();
		pf->filedata = new char[size + 1];
		memcpy(pf->filedata, preloaded_content->data(), size);
		pf->filedata[size] = '\0';
		}
	else
		{
		FILE* f = fopen(policy_filename, "r");

		if ( ! f )
			{
			debug_msg("Could not open policy file: %s.\n", policy_filename);
			return false;
			}

		struct stat st;
		if ( fstat(fileno(f), &st) != 0 )
			{
			char buf[256];
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Error("fstat failed on %s: %s", policy_filename, buf);
			fclose(f);
			return false;
			}

		pf->lmtime = st.st_mtime;
		off_t size = st.st_size;

		// ### This code is not necessarily Unicode safe!
		// (probably fine with UTF-8)
		pf->filedata = new char[size + 1];
		size_t n = fread(pf->filedata, 1, size, f);
		if ( ferror(f) )
			reporter->InternalError("Failed to fread() file data");
		pf->filedata[n] = 0;
		fclose(f);
		}

	// Separate the string by newlines.
	pf->lines.push_back(pf->filedata);

	for ( char* iter = pf->filedata; *iter; ++iter )
		{
		if ( *iter == '\n' )
			{
			*iter = 0;
			if ( *(iter + 1) )
				pf->lines.push_back(iter + 1);
			}
		}

	for ( int i = 0; i < int(pf->lines.size()); ++i )
		assert(pf->lines[i][0] != '\n');

	return true;
	}

// REMEMBER: line number arguments are indexed from 0.
bool PrintLines(const char* policy_filename, unsigned int start_line, unsigned int how_many_lines,
                bool show_numbers)
	{
	if ( ! policy_filename )
		return true;

	FILE* throwaway = fopen(policy_filename, "r");
	if ( ! throwaway )
		{
		debug_msg("Could not open policy file: %s.\n", policy_filename);
		return false;
		}

	fclose(throwaway);

	PolicyFileMap::iterator match;
	match = policy_files.find(policy_filename);

	if ( match == policy_files.end() )
		{
		match = policy_files.find(policy_filename);
		if ( match == policy_files.end() )
			{
			debug_msg("Policy file %s was not loaded.\n", policy_filename);
			return false;
			}
		}

	PolicyFile* pf = match->second;

	if ( start_line < 1 )
		start_line = 1;

	if ( start_line > pf->lines.size() )
		{
		debug_msg("Line number %d out of range; %s has %d lines\n", start_line, policy_filename,
		          int(pf->lines.size()));
		return false;
		}

	if ( start_line + how_many_lines - 1 > pf->lines.size() )
		how_many_lines = pf->lines.size() - start_line + 1;

	for ( unsigned int i = 0; i < how_many_lines; ++i )
		{
		if ( show_numbers )
			debug_msg("%d\t", i + start_line);

		const char* line = pf->lines[start_line + i - 1];
		debug_msg("%s\n", line);
		}

	return true;
	}

	} // namespace zeek::detail
