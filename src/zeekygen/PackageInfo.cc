// See the file "COPYING" in the main distribution directory for copyright.

#include "PackageInfo.h"
#include "utils.h"

#include "Reporter.h"

#include <fstream>
#include <errno.h>

using namespace std;
using namespace zeekygen;

PackageInfo::PackageInfo(const string& arg_name)
    : Info(),
      pkg_name(arg_name), readme()
	{
	string readme_file = zeek::util::find_file(pkg_name + "/README", zeek::util::zeek_path());

	if ( readme_file.empty() )
		return;

	ifstream f(readme_file.c_str());

	if ( ! f.is_open() )
		zeek::reporter->InternalWarning("Zeekygen failed to open '%s': %s",
		                                readme_file.c_str(), strerror(errno));

	string line;

	while ( getline(f, line) )
		readme.push_back(line);

	if ( f.bad() )
		zeek::reporter->InternalWarning("Zeekygen error reading '%s': %s",
		                                readme_file.c_str(), strerror(errno));
	}

string PackageInfo::DoReStructuredText(bool roles_only) const
	{
	string rval = zeek::util::fmt(":doc:`%s </scripts/%s/index>`\n\n", pkg_name.c_str(),
	                              pkg_name.c_str());

	for ( size_t i = 0; i < readme.size(); ++i )
		rval += "   " + readme[i] + "\n";

	return rval;
	}

time_t PackageInfo::DoGetModificationTime() const
	{
	string readme_file = zeek::util::find_file(pkg_name + "/README", zeek::util::zeek_path());

	if ( readme_file.empty() )
		return 0;

	return zeekygen::get_mtime(readme_file);
	}
