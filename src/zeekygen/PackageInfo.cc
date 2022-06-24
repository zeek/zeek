// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/PackageInfo.h"

#include <cerrno>
#include <fstream>

#include "zeek/Reporter.h"
#include "zeek/zeekygen/utils.h"

using namespace std;

namespace zeek::zeekygen::detail
	{

PackageInfo::PackageInfo(const string& arg_name) : Info(), pkg_name(arg_name), readme()
	{
	string readme_file = util::find_file(pkg_name + "/README", util::zeek_path());

	if ( readme_file.empty() )
		return;

	ifstream f(readme_file.c_str());

	if ( ! f.is_open() )
		reporter->InternalWarning("Zeekygen failed to open '%s': %s", readme_file.c_str(),
		                          strerror(errno));

	string line;

	while ( getline(f, line) )
		readme.push_back(line);

	if ( f.bad() )
		reporter->InternalWarning("Zeekygen error reading '%s': %s", readme_file.c_str(),
		                          strerror(errno));
	}

string PackageInfo::DoReStructuredText(bool roles_only) const
	{
	string rval = util::fmt(":doc:`%s </scripts/%s/index>`\n\n", pkg_name.c_str(),
	                        pkg_name.c_str());

	for ( size_t i = 0; i < readme.size(); ++i )
		rval += "   " + readme[i] + "\n";

	return rval;
	}

time_t PackageInfo::DoGetModificationTime() const
	{
	string readme_file = util::find_file(pkg_name + "/README", util::zeek_path());

	if ( readme_file.empty() )
		return 0;

	return get_mtime(readme_file);
	}

	} // namespace zeek::zeekygen::detail
