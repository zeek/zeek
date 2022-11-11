#pragma once

#include <list>
#include <map>
#include <string>
#include <utility>

#include "zeek/util.h"

namespace zeek::detail
	{

class Stmt;

/**
 * A simple class for managing stats of Zeek script coverage across Zeek runs.
 */
class ScriptCoverageManager
	{
public:
	ScriptCoverageManager();
	virtual ~ScriptCoverageManager();

	/**
	 * Imports Zeek script Stmt usage information from file pointed to by
	 * environment variable ZEEK_PROFILER_FILE.
	 *
	 * @return: true if usage info was read, otherwise false.
	 */
	bool ReadStats();

	/**
	 * Combines usage stats from current run with any read from ReadStats(),
	 * then writes information to file pointed to by environment variable
	 * ZEEK_PROFILER_FILE.  If the value of that env. variable ends with
	 * ".XXXXXX" (exactly 6 X's), then it is first passed through mkstemp
	 * to get a unique file.
	 *
	 * @return: true when usage info is written, otherwise false.
	 */
	bool WriteStats();

	void SetDelim(char d) { delim = d; }

	void IncIgnoreDepth() { ignoring++; }
	void DecIgnoreDepth() { ignoring--; }

	void AddStmt(Stmt* s);

private:
	/**
	 * The current, global ScriptCoverageManager instance creates this list at parse-time.
	 */
	std::list<Stmt*> stmts;

	/**
	 * Indicates whether new statements will not be considered as part of
	 * coverage statistics because it was marked with the @no-test tag.
	 */
	uint32_t ignoring;

	/**
	 * The character to use to delimit ScriptCoverageManager output files.  Default is '\t'.
	 */
	char delim;

	/**
	 * This maps Stmt location-desc pairs to the total number of times that
	 * Stmt has been executed.  The map can be initialized from a file at
	 * startup time and modified at shutdown time before writing back
	 * to a file.
	 */
	std::map<std::pair<std::string, std::string>, uint64_t> usage_map;

	/**
	 * A canonicalization routine for Stmt descriptions containing characters
	 * that don't agree with the output format of ScriptCoverageManager.
	 */
	struct canonicalize_desc
		{
		char delim;

		void operator()(char& c)
			{
			if ( c == '\n' )
				c = ' ';
			if ( c == delim )
				c = ' ';
			}
		};
	};

extern ScriptCoverageManager script_coverage_mgr;

	} // namespace zeek::detail
