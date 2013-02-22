#include <string>

#include "Hash.h"
#include "util.h"

using namespace file_analysis;

Hash::Hash(Info* arg_info, ActionTag tag, HashVal* hv)
	: Action(arg_info, tag), hash(hv)
	{
	hash->Init();
	}

Hash::~Hash()
	{
	// maybe it's all there...
	Finalize();
	delete hash;
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
	int i = GetResultFieldOffset();

	if ( i < 0 )
		reporter->InternalError("Hash Action result field not found");

	info->Results()->Assign(i, sv);
	}
