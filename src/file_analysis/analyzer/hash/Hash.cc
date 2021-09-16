// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/analyzer/hash/Hash.h"

#include <string>

#include "zeek/Event.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/util.h"

namespace zeek::file_analysis::detail
	{

Hash::Hash(RecordValPtr args, file_analysis::File* file, HashVal* hv, const char* arg_kind)
	: file_analysis::Analyzer(file_mgr->GetComponentTag(util::to_upper(arg_kind).c_str()),
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

	event_mgr.Enqueue(file_hash, GetFile()->ToVal(), make_intrusive<StringVal>(kind), hash->Get());
	}

	} // namespace zeek::file_analysis::detail
