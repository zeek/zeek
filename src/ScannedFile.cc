#include "zeek/ScannedFile.h"

#include <sys/errno.h>
#include <limits.h> // for PATH_MAX

#include "zeek/DebugLogger.h"
#include "zeek/Reporter.h"

namespace zeek::detail {

std::list<ScannedFile> files_scanned;
std::vector<std::string> sig_files;

ScannedFile::ScannedFile(int arg_include_level,
                         std::string arg_name,
                         bool arg_skipped,
                         bool arg_prefixes_checked)
	: include_level(arg_include_level),
	  skipped(arg_skipped),
	  prefixes_checked(arg_prefixes_checked),
	  name(std::move(arg_name))
	{
	if ( name == canonical_stdin_path )
		canonical_path = canonical_stdin_path;
	else
		{
		char buf[PATH_MAX];
		auto res = realpath(name.data(), buf);

		if ( ! res )
			zeek::reporter->FatalError("failed to get realpath() of %s: %s",
			                           name.data(), strerror(errno));

		canonical_path = res;
		}
	}

bool ScannedFile::AlreadyScanned() const
	{
	auto rval = false;

	for ( const auto& it : files_scanned )
		if ( it.canonical_path == canonical_path )
			{
			rval = true;
			break;
			}

	DBG_LOG(zeek::DBG_SCRIPTS, "AlreadyScanned result (%d) %s", rval, canonical_path.data());
	return rval;
	}

} // namespace zeek::detail
