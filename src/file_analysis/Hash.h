#ifndef FILE_ANALYSIS_HASH_H
#define FILE_ANALYSIS_HASH_H

#include <string>

#include "Val.h"
#include "OpaqueVal.h"
#include "Info.h"
#include "Action.h"

namespace file_analysis {

/**
 * An action to produce a hash of file contents.
 */
class Hash : public Action {
public:

	virtual ~Hash();

	virtual bool DeliverStream(const u_char* data, uint64 len);

	virtual bool EndOfFile();

	virtual bool Undelivered(uint64 offset, uint64 len);

protected:

	Hash(RecordVal* args, Info* info, HashVal* hv, const char* field);

	void Finalize();

	HashVal* hash;
	bool fed;
	int result_field_idx;
};

class MD5 : public Hash {
public:

	static Action* Instantiate(RecordVal* args, Info* info)
		{ return new MD5(args, info); }

protected:

	MD5(RecordVal* args, Info* info)
		: Hash(args, info, new MD5Val(), "md5")
		{}
};

class SHA1 : public Hash {
public:

	static Action* Instantiate(RecordVal* args, Info* info)
		{ return new SHA1(args, info); }

protected:

	SHA1(RecordVal* args, Info* info)
		: Hash(args, info, new SHA1Val(), "sha1")
		{}
};

class SHA256 : public Hash {
public:

	static Action* Instantiate(RecordVal* args, Info* info)
		{ return new SHA256(args, info); }

protected:

	SHA256(RecordVal* args, Info* info)
		: Hash(args, info, new SHA256Val(), "sha256")
		{}
};

} // namespace file_analysis

#endif
