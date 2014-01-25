// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BROXYGEN_PACKAGEINFO_H
#define BROXYGEN_PACKAGEINFO_H

#include "Info.h"

#include <string>
#include <vector>

namespace broxygen {

/**
 * Information about a Bro script package.
 */
class PackageInfo : public Info {

public:

	/**
	 * Ctor.
	 * @param name The name of the Bro script package (relative path from a
	 * component within BROPATH.
	 */
	PackageInfo(const std::string& name);

	/**
	 * @return The content of the package's README file, each line being
	 * an element in the returned vector.  If the package has no README, the
	 * vector is empty.
	 */
	std::vector<std::string> GetReadme() const
		{ return readme; }

private:

	time_t DoGetModificationTime() const;

	std::string DoName() const
		{ return pkg_name; }

	std::string DoReStructuredText(bool roles_only) const;

	std::string pkg_name;
	std::vector<std::string> readme;
};

} // namespace broxygen

#endif
