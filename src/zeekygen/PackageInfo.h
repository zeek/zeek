// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <time.h> // for time_t
#include <string>
#include <vector>

#include "zeek/zeekygen/Info.h"

namespace zeek::zeekygen::detail {

/**
 * Information about a Zeek script package.
 */
class PackageInfo : public Info {

public:

	/**
	 * Ctor.
	 * @param name The name of the Zeek script package (relative path from a
	 * component within ZEEKPATH).
	 */
	explicit PackageInfo(const std::string& name);

	/**
	 * @return The content of the package's README file, each line being
	 * an element in the returned vector.  If the package has no README, the
	 * vector is empty.
	 */
	std::vector<std::string> GetReadme() const
		{ return readme; }

private:

	time_t DoGetModificationTime() const override;

	std::string DoName() const override
		{ return pkg_name; }

	std::string DoReStructuredText(bool roles_only) const override;

	std::string pkg_name;
	std::vector<std::string> readme;
};

} // namespace zeek::zeekygen::detail
