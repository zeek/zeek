#ifndef FILE_ANALYSIS_PENDINGFILE_H
#define FILE_ANALYSIS_PENDINGFILE_H

#include "AnalyzerTags.h"
#include "Conn.h"
#include "Info.h"

namespace file_analysis {

class PendingFile {
public:

	virtual ~PendingFile();

	virtual void Finish(const string& handle) const = 0;

protected:

	PendingFile(Connection* arg_conn,
	            AnalyzerTag::Tag arg_tag = AnalyzerTag::Error);

	Info* GetInfo(const string& handle) const;

	Connection* conn;
	AnalyzerTag::Tag tag;
};

class PendingDataInChunk : public PendingFile {
public:

	PendingDataInChunk(const u_char* arg_data, uint64 arg_len,
	                   uint64 arg_offset, AnalyzerTag::Tag arg_tag,
	                   Connection* arg_conn);

	virtual ~PendingDataInChunk();

	virtual void Finish(const string& handle) const;

protected:

	const u_char* data;
	uint64 len;
	uint64 offset;
};

class PendingDataInStream : public PendingFile {
public:

	PendingDataInStream(const u_char* arg_data, uint64 arg_len,
	                    AnalyzerTag::Tag arg_tag, Connection* arg_conn);

	virtual ~PendingDataInStream();

	virtual void Finish(const string& handle) const;

protected:

	const u_char* data;
	uint64 len;
};

class PendingGap : public PendingFile {
public:

	PendingGap(uint64 arg_offset, uint64 arg_len, AnalyzerTag::Tag arg_tag,
	           Connection* arg_conn);

	virtual void Finish(const string& handle) const;

protected:

	uint64 offset;
	uint64 len;
};

class PendingEOF : public PendingFile {
public:

	PendingEOF(AnalyzerTag::Tag arg_tag, Connection* arg_conn);

	virtual void Finish(const string& handle) const;
};

class PendingSize : public PendingFile {
public:

	PendingSize(uint64 arg_size, AnalyzerTag::Tag arg_tag,
	            Connection* arg_conn);

	virtual void Finish(const string& handle) const;

protected:

	uint64 size;
};

} // namespace file_analysis

#endif
