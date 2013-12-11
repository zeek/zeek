// See the file "COPYING" in the main distribution directory for copyright.

#include "PackageInfo.h"
#include "utils.h"

#include "Reporter.h"

#include <fstream>
#include <errno.h>

using namespace std;
using namespace broxygen;

PackageInfo::PackageInfo(const string& arg_name)
    : Info(),
      pkg_name(arg_name), readme()
	{
	string readme_file = find_file(pkg_name + "/README", bro_path());

	if ( readme_file.empty() )
		return;

	ifstream f(readme_file.c_str());

	if ( ! f.is_open() )
		reporter->InternalWarning("Broxygen failed to open '%s': %s",
		                          readme_file.c_str(), strerror(errno));

	string line;

	while ( getline(f, line) )
		readme.push_back(line);

	if ( f.bad() )
		reporter->InternalWarning("Broxygen error reading '%s': %s",
		                          readme_file.c_str(), strerror(errno));
	}

string PackageInfo::DoReStructuredText(bool roles_only) const
	{
	string rval = fmt(":doc:`%s </scripts/%s/index>`\n\n", pkg_name.c_str(),
	                  pkg_name.c_str());

	for ( size_t i = 0; i < readme.size(); ++i )
		rval += "   " + readme[i] + "\n";

	return rval;
	}

time_t PackageInfo::DoGetModificationTime() const
	{
	string readme_file = find_file(pkg_name + "/README", bro_path());

	if ( readme_file.empty() )
		return 0;

	return broxygen::get_mtime(readme_file);
	}
