#include "PendingFile.h"
#include "Manager.h"

using namespace file_analysis;

PendingFile::PendingFile(const u_char* arg_data, uint64 arg_len,
                         uint64 arg_offset, Connection* arg_conn,
	                     bool arg_is_orig)
	: is_linear(false), data(arg_data), len(arg_len), offset(arg_offset),
	  conn(arg_conn), is_orig(arg_is_orig)
	{
	Ref(conn);
	}

PendingFile::PendingFile(const u_char* arg_data, uint64 arg_len,
                         Connection* arg_conn, bool arg_is_orig)
	: is_linear(true), data(arg_data), len(arg_len), offset(0),
	  conn(arg_conn), is_orig(arg_is_orig)
	{
	Ref(conn);
	}

PendingFile::PendingFile(const PendingFile& other)
	: is_linear(other.is_linear), data(other.data), len(other.len),
	  offset(other.offset), conn(other.conn), is_orig(other.is_orig)
	{
	Ref(conn);
	}

PendingFile& PendingFile::operator=(const PendingFile& other)
	{
	// handle self-assign for correct reference counting
	if ( this == &other ) return *this;

	Unref(conn);

	is_linear = other.is_linear;
	data = other.data;
	len = other.len;
	offset = other.offset;
	conn = other.conn;
	is_orig = other.is_orig;

	Ref(conn);

	return *this;
	}

PendingFile::~PendingFile()
	{
	Unref(conn);
	}

void PendingFile::Retry() const
	{
	if ( is_linear )
		file_mgr->DataIn(data, len, conn, is_orig, false);
	else
		file_mgr->DataIn(data, len, offset, conn, is_orig, false);
	}
