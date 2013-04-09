#include "PendingFile.h"
#include "Manager.h"

using namespace file_analysis;

static void copy_data(const u_char** dst, const u_char* src, uint64 len)
	{
	u_char* tmp = new u_char[len];
	memcpy(tmp, src, len);
	*dst = tmp;
	}

static string conn_str(Connection* c)
	{
	char op[256], rp[256];
	modp_ulitoa10(ntohs(c->OrigPort()), op);
	modp_ulitoa10(ntohs(c->RespPort()), rp);
	string rval = c->OrigAddr().AsString() + ":" + op + "->" +
	              c->RespAddr().AsString() + ":" + rp;
	return rval;
	}

PendingFile::PendingFile(Connection* arg_conn, AnalyzerTag::Tag arg_tag)
	: conn(arg_conn), tag(arg_tag)
	{
	Ref(conn);
	DBG_LOG(DBG_FILE_ANALYSIS, "New pending file: %s", conn_str(conn).c_str());
	}

PendingFile::~PendingFile()
	{
	Unref(conn);
	DBG_LOG(DBG_FILE_ANALYSIS, "Delete pending file: %s",
	        conn_str(conn).c_str());
	}

File* PendingFile::GetFile(const string& handle) const
	{
	return file_mgr->GetFile(handle, conn, tag);
	}

PendingDataInChunk::PendingDataInChunk(const u_char* arg_data, uint64 arg_len,
                                       uint64 arg_offset,
                                       AnalyzerTag::Tag arg_tag,
                                       Connection* arg_conn)
	: PendingFile(arg_conn, arg_tag), len(arg_len),
	  offset(arg_offset)
	{
	copy_data(&data, arg_data, len);
	}

void PendingDataInChunk::Finish(const string& handle) const
	{
	file_mgr->DataIn(data, len, offset, GetFile(handle));
	}

PendingDataInChunk::~PendingDataInChunk()
	{
	delete [] data;
	}

PendingDataInStream::PendingDataInStream(const u_char* arg_data, uint64 arg_len,
                                         AnalyzerTag::Tag arg_tag,
                                         Connection* arg_conn)
	: PendingFile(arg_conn, arg_tag), len(arg_len)
	{
	copy_data(&data, arg_data, len);
	}

void PendingDataInStream::Finish(const string& handle) const
	{
	file_mgr->DataIn(data, len, GetFile(handle));
	}

PendingDataInStream::~PendingDataInStream()
	{
	delete [] data;
	}

PendingGap::PendingGap(uint64 arg_offset, uint64 arg_len,
                       AnalyzerTag::Tag arg_tag, Connection* arg_conn)
	: PendingFile(arg_conn, arg_tag), offset(arg_offset),
	  len(arg_len)
	{
	}

void PendingGap::Finish(const string& handle) const
	{
	file_mgr->Gap(offset, len, GetFile(handle));
	}

PendingEOF::PendingEOF(AnalyzerTag::Tag arg_tag, Connection* arg_conn)
	: PendingFile(arg_conn, arg_tag)
	{
	}

void PendingEOF::Finish(const string& handle) const
	{
	file_mgr->EndOfFile(handle);
	}

PendingSize::PendingSize(uint64 arg_size, AnalyzerTag::Tag arg_tag,
                         Connection* arg_conn)
	: PendingFile(arg_conn, arg_tag), size(arg_size)
	{
	}

void PendingSize::Finish(const string& handle) const
	{
	file_mgr->SetSize(size, GetFile(handle));
	}
