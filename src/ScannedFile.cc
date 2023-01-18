#include "zeek/ScannedFile.h"

#include <cerrno>
#include <climits> // for PATH_MAX

#include "zeek/DebugLogger.h"
#include "zeek/Reporter.h"

namespace zeek::detail
	{

std::list<ScannedFile> files_scanned;
std::vector<SignatureFile> sig_files;

ScannedFile::ScannedFile(int arg_include_level, std::string arg_name, bool arg_skipped,
                         bool arg_prefixes_checked)
	: include_level(arg_include_level), skipped(arg_skipped),
	  prefixes_checked(arg_prefixes_checked), name(std::move(arg_name))
	{
	if ( name == canonical_stdin_path )
		canonical_path = canonical_stdin_path;
	else
		{
		std::error_code ec;
		auto canon = filesystem::canonical(name, ec);
		if ( ec )
			zeek::reporter->FatalError("failed to get canonical path of %s: %s", name.data(),
			                           ec.message().c_str());

		canonical_path = canon.string();
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

SignatureFile::SignatureFile(std::string file) : file(std::move(file)) { }

SignatureFile::SignatureFile(std::string file, std::string full_path, Location load_location)
	: file(std::move(file)), full_path(std::move(full_path)),
	  load_location(std::move(load_location))
	{
	}

	} // namespace zeek::detail
