// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Hash.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

namespace zeek::file_analysis::detail {

Hash::Hash(zeek::RecordValPtr args, zeek::file_analysis::File* file,
           zeek::HashVal* hv, const char* arg_kind)
	: zeek::file_analysis::Analyzer(zeek::file_mgr->GetComponentTag(to_upper(arg_kind).c_str()),
	                                std::move(args), file),
	  hash(hv), fed(false), kind(arg_kind)
	{
	hash->Init();
	}

Hash::~Hash()
	{
	Unref(hash);
	}

bool Hash::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! hash->IsValid() )
		return false;

	if ( ! fed )
		fed = len > 0;

	hash->Feed(data, len);
	return true;
	}

bool Hash::EndOfFile()
	{
	Finalize();
	return false;
	}

bool Hash::Undelivered(uint64_t offset, uint64_t len)
	{
	return false;
	}

void Hash::Finalize()
	{
	if ( ! hash->IsValid() || ! fed )
		return;

	if ( ! file_hash )
		return;

	zeek::event_mgr.Enqueue(file_hash,
	                        GetFile()->ToVal(),
	                        zeek::make_intrusive<zeek::StringVal>(kind),
	                        hash->Get()
	);
	}

} // namespace zeek::file_analysis::detail
