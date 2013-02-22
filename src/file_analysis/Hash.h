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

	Hash(Info* arg_info, ActionTag arg_tag, HashVal* hv);

	void Finalize();

	virtual int GetResultFieldOffset() const = 0;

	HashVal* hash;
};

class MD5 : public Hash {
public:

	static Action* Instantiate(const RecordVal* args, Info* info)
		{ return new MD5(info); }

protected:

	MD5(Info* arg_info)
	 : Hash(arg_info, BifEnum::FileAnalysis::ACTION_MD5, new MD5Val()) {}

	virtual int GetResultFieldOffset() const
		{ return BifType::Record::FileAnalysis::ActionResults->
		  FieldOffset("md5"); }
};

class SHA1 : public Hash {
public:

	static Action* Instantiate(const RecordVal* args, Info* info)
		{ return new SHA1(info); }

protected:

	SHA1(Info* arg_info)
	 : Hash(arg_info, BifEnum::FileAnalysis::ACTION_SHA1, new SHA1Val()) {}

	virtual int GetResultFieldOffset() const
		{ return BifType::Record::FileAnalysis::ActionResults->
		  FieldOffset("sha1"); }
};

class SHA256 : public Hash {
public:

	static Action* Instantiate(const RecordVal* args, Info* info)
		{ return new SHA256(info); }

protected:

	SHA256(Info* arg_info)
	 : Hash(arg_info, BifEnum::FileAnalysis::ACTION_SHA256, new SHA256Val()) {}

	virtual int GetResultFieldOffset() const
		{ return BifType::Record::FileAnalysis::ActionResults->
		  FieldOffset("sha256"); }
};

} // namespace file_analysis

#endif
