#include <string>

#include "Hash.h"
#include "util.h"

using namespace file_analysis;

Hash::Hash(RecordVal* args, Info* info, HashVal* hv, const char* field)
	: Action(args, info), hash(hv)
	{
	using BifType::Record::FileAnalysis::ActionResults;
	if ( (result_field_idx = ActionResults->FieldOffset(field)) < 0 )
		reporter->InternalError("Missing ActionResults field: %s", field);
	hash->Init();
	}

Hash::~Hash()
	{
	// maybe it's all there...
	Finalize();
	Unref(hash);
	}

bool Hash::DeliverStream(const u_char* data, uint64 len)
	{
	Action::DeliverStream(data, len);

	if ( ! hash->IsValid() ) return false;

	hash->Feed(data, len);
	return true;
	}

bool Hash::EndOfFile()
	{
	Action::EndOfFile();
	Finalize();
	return false;
	}

bool Hash::Undelivered(uint64 offset, uint64 len)
	{
	return false;
	}

void Hash::Finalize()
	{
	if ( ! hash->IsValid() ) return;

	StringVal* sv = hash->Get();
	info->GetResults(args)->Assign(result_field_idx, sv);
	}
