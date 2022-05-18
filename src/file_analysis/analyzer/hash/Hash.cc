// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/analyzer/hash/Hash.h"

#include <string>

#include "zeek/Event.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/util.h"

namespace zeek::file_analysis::detail
	{

StringValPtr MD5::kind_val = make_intrusive<StringVal>("md5");
StringValPtr SHA1::kind_val = make_intrusive<StringVal>("sha1");
StringValPtr SHA256::kind_val = make_intrusive<StringVal>("sha256");

Hash::Hash(RecordValPtr args, file_analysis::File* file, HashVal* hv, StringValPtr arg_kind)
	: file_analysis::Analyzer(file_mgr->GetComponentTag(util::to_upper(arg_kind->ToStdString())),
                              std::move(args), file),
	  hash(hv), fed(false), kind(std::move(arg_kind))
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

	event_mgr.Enqueue(file_hash, GetFile()->ToVal(), kind, hash->Get());
	}

	} // namespace zeek::file_analysis::detail
