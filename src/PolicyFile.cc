#include "zeek-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#include <map>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <vector>

#include "Debug.h"
#include "util.h"
#include "PolicyFile.h"
#include "Reporter.h"

using namespace std;

struct PolicyFile {
	PolicyFile ()	{ filedata = nullptr; lmtime = 0; }
	~PolicyFile ()	{ delete [] filedata; filedata = nullptr; }

	time_t lmtime;
	char* filedata;
	vector<const char*> lines;
};

typedef map<string, PolicyFile*> PolicyFileMap;
static PolicyFileMap policy_files;

namespace zeek::detail {

int how_many_lines_in(const char* policy_filename)
	{
	if ( ! policy_filename )
		zeek::reporter->InternalError("NULL value passed to how_many_lines_in\n");

	FILE* throwaway = fopen(policy_filename, "r");
	if ( ! throwaway )
		{
		zeek::detail::debug_msg("No such policy file: %s.\n", policy_filename);
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
			zeek::detail::debug_msg("Policy file %s was not loaded.\n", policy_filename);
			return -1;
			}
		}

	PolicyFile* pf = match->second;
	return pf->lines.size();
	}

bool LoadPolicyFileText(const char* policy_filename)
	{
	if ( ! policy_filename )
		return true;

	FILE* f = fopen(policy_filename, "r");

	if ( ! f )
		{
		zeek::detail::debug_msg("No such policy file: %s.\n", policy_filename);
		return false;
		}

	PolicyFile* pf = new PolicyFile;

	if ( policy_files.find(policy_filename) != policy_files.end() )
		zeek::detail::debug_msg("Policy file %s already loaded\n", policy_filename);

	policy_files.insert(PolicyFileMap::value_type(policy_filename, pf));

	struct stat st;
	if ( fstat(fileno(f), &st) != 0 )
		{
		char buf[256];
		zeek::util::zeek_strerror_r(errno, buf, sizeof(buf));
		zeek::reporter->Error("fstat failed on %s: %s", policy_filename, buf);
		fclose(f);
		return false;
		}

	pf->lmtime = st.st_mtime;
	off_t size = st.st_size;

	// ### This code is not necessarily Unicode safe!
	// (probably fine with UTF-8)
	pf->filedata = new char[size+1];
	if ( fread(pf->filedata, size, 1, f) != 1 )
        zeek::reporter->InternalError("Failed to fread() file data");
	pf->filedata[size] = 0;
	fclose(f);

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
bool PrintLines(const char* policy_filename, unsigned int start_line,
		unsigned int how_many_lines, bool show_numbers)
	{
	if ( ! policy_filename )
		return true;

	FILE* throwaway = fopen(policy_filename, "r");
	if ( ! throwaway )
		{
		zeek::detail::debug_msg("No such policy file: %s.\n", policy_filename);
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
			zeek::detail::debug_msg("Policy file %s was not loaded.\n", policy_filename);
			return false;
			}
		}

	PolicyFile* pf = match->second;

	if ( start_line < 1 )
		start_line = 1;

	if ( start_line > pf->lines.size() )
		{
		zeek::detail::debug_msg("Line number %d out of range; %s has %d lines\n",
			start_line, policy_filename, int(pf->lines.size()));
		return false;
		}

	if ( start_line + how_many_lines - 1 > pf->lines.size() )
		how_many_lines = pf->lines.size() - start_line + 1;

	for ( unsigned int i = 0; i < how_many_lines; ++i )
		{
		if ( show_numbers )
			zeek::detail::debug_msg("%d\t", i + start_line);

		const char* line = pf->lines[start_line + i - 1];
		zeek::detail::debug_msg("%s\n", line);
		}

	return true;
	}

} // namespace zeek::detail
