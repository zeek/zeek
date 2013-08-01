// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Hash.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

Hash::Hash(RecordVal* args, File* file, HashVal* hv, const char* arg_kind)
	: file_analysis::Analyzer(file_mgr->GetComponentTag(to_upper(arg_kind).c_str()), args, file), hash(hv), fed(false), kind(arg_kind)
	{
	hash->Init();
	}

Hash::~Hash()
	{
	Unref(hash);
	}

bool Hash::DeliverStream(const u_char* data, uint64 len)
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

bool Hash::Undelivered(uint64 offset, uint64 len)
	{
	return false;
	}

void Hash::Finalize()
	{
	if ( ! hash->IsValid() || ! fed )
		return;

	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(new StringVal(kind));
	vl->append(hash->Get());

	mgr.QueueEvent(file_hash, vl);
	}
