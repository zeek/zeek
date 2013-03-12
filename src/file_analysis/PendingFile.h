#ifndef FILE_ANALYSIS_PENDINGFILE_H
#define FILE_ANALYSIS_PENDINGFILE_H

#include "Conn.h"

namespace file_analysis {

class PendingFile {
public:

	PendingFile(const u_char* arg_data, uint64 arg_len, uint64 arg_offset,
	            Connection* arg_conn, bool arg_is_orig);

	PendingFile(const u_char* arg_data, uint64 arg_len,
	            Connection* arg_conn, bool arg_is_orig);

	PendingFile(const PendingFile& other);

	PendingFile& operator=(const PendingFile& other);

	~PendingFile();

	void Retry() const;

private:

	bool is_linear;
	const u_char* data;
	uint64 len;
	uint64 offset;
	Connection* conn;
	bool is_orig;
};

} // namespace file_analysis

#endif
