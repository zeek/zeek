// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <time.h> // for time_t
#include <string>
#include <vector>

#include "zeek/zeekygen/Target.h"

namespace zeek::zeekygen::detail {

class Info;

/**
 * Manages the generation of reStructuredText documents corresponding to
 * particular targets that are specified in a config file.  The config file
 * is a simple list of one target per line, with the target format being
 * a tab-delimited list of target-type, target-pattern, and target-output-file.
 */
class Config {

public:

	/**
	 * Read a Zeekygen configuration file, parsing all targets in it.
	 * @param file The file containing a list of Zeekygen targets.  If it's
	 * an empty string most methods are a no-op.
	 * @param delim The delimiter between target fields.
	 */
	explicit Config(const std::string& file, const std::string& delim = "\t");

	/**
	  * Destructor, cleans up targets created when parsing config file.
	  */
	~Config();

	/**
	 * Resolves dependency information for each target.
	 * @param infos All known information objects for documentable things.
	 */
	void FindDependencies(const std::vector<Info*>& infos);

	/**
	 * Build each Zeekygen target (i.e. write out the reST documents to disk).
	 */
	void GenerateDocs() const;

	/**
	 * @return The modification time of the config file, or 0 if config
	 * file was specified by an empty string.
	 */
	time_t GetModificationTime() const;

private:

	std::string file;
	std::vector<Target*> targets;
	TargetFactory target_factory;
};

} // namespace zeek::zeekygen::detail
