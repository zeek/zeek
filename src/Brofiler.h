#ifndef BROFILER_H_
#define BROFILER_H_

#include <map>
#include <utility>
#include <list>
#include <Stmt.h>


/**
 * A simple class for managing stats of Bro script coverage across Bro runs.
 */
class Brofiler {
public:
	Brofiler();
	virtual ~Brofiler();

	/**
	 * Imports Bro script Stmt usage information from file pointed to by
	 * environment variable BROFILER_FILE.
	 */
	void ReadStats();

	/**
	 * Combines usage stats from current run with any read from ReadStats(),
	 * then writes information to file pointed to by environment variable
	 * BROFILER_FILE.
	 */
	void WriteStats();

	void SetDelim(char d) { delim = d; }

	/**
	 * The current, global Brofiler instance creates this list at parse-time.
	 */
	list<const Stmt*> stmts;

private:
	/**
	 *
	 * This maps Stmt location-desc pairs to the total number of times that
	 * Stmt has been executed.  The map can be initialized from a file at
	 * startup time and modified at shutdown time before writing back
	 * to a file.
	 */
	map<pair<string, string>, uint64> usage_map;

	/**
	 * The character to use to delimit Brofiler output files.  Default is '\t'.
	 */
	char delim;

	/**
	 * A canonicalization routine for Stmt descriptions containing characters
	 * that don't agree with the output format of Brofiler.
	 */
	struct canonicalize_desc {
		void operator() (char& c)
			{
			if ( c == '\n' ) c = ' ';
			}
	};
};

#endif /* BROFILER_H_ */
