// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_HASH_H
#define FILE_ANALYSIS_HASH_H

#include <string>

#include "Val.h"
#include "OpaqueVal.h"
#include "File.h"
#include "Analyzer.h"

namespace file_analysis {

/**
 * An analyzer to produce a hash of file contents.
 */
class Hash : public file_analysis::Analyzer {
public:
	virtual ~Hash();

	virtual bool DeliverStream(const u_char* data, uint64 len);

	virtual bool EndOfFile();

	virtual bool Undelivered(uint64 offset, uint64 len);

protected:
	Hash(RecordVal* args, File* file, HashVal* hv, const char* kind);

	void Finalize();

private:
	HashVal* hash;
	bool fed;
	const char* kind;
};

class MD5 : public Hash {
public:
	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return file_hash ? new MD5(args, file) : 0; }

protected:
	MD5(RecordVal* args, File* file)
		: Hash(args, file, new MD5Val(), "md5")
		{}
};

class SHA1 : public Hash {
public:
	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return file_hash ? new SHA1(args, file) : 0; }

protected:
	SHA1(RecordVal* args, File* file)
		: Hash(args, file, new SHA1Val(), "sha1")
		{}
};

class SHA256 : public Hash {
public:
	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return file_hash ? new SHA256(args, file) : 0; }

protected:
	SHA256(RecordVal* args, File* file)
		: Hash(args, file, new SHA256Val(), "sha256")
		{}
};

} // namespace file_analysis

#endif
