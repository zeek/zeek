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

PendingFile::PendingFile(Connection* arg_conn, bool arg_is_orig,
                         AnalyzerTag::Tag arg_tag)
	: conn(arg_conn), is_orig(arg_is_orig), creation_time(network_time),
	  tag(arg_tag)
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

bool PendingFile::IsStale() const
	{
	using BifConst::FileAnalysis::pending_file_timeout;
	if ( creation_time + pending_file_timeout < network_time )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Stale pending file: %s",
		        conn_str(conn).c_str());
		return true;
		}
	return false;
	}

PendingDataInChunk::PendingDataInChunk(const u_char* arg_data, uint64 arg_len,
                                       uint64 arg_offset,
                                       AnalyzerTag::Tag arg_tag,
                                       Connection* arg_conn, bool arg_is_orig)
	: PendingFile(arg_conn, arg_is_orig, arg_tag), len(arg_len),
	  offset(arg_offset)
	{
	copy_data(&data, arg_data, len);
	}

bool PendingDataInChunk::Retry() const
	{
	return file_mgr->DataIn(data, len, offset, tag, conn, is_orig);
	}

PendingDataInChunk::~PendingDataInChunk()
	{
	delete [] data;
	}

PendingDataInStream::PendingDataInStream(const u_char* arg_data, uint64 arg_len,
                                         AnalyzerTag::Tag arg_tag,
                                         Connection* arg_conn, bool arg_is_orig)
	: PendingFile(arg_conn, arg_is_orig, arg_tag), len(arg_len)
	{
	copy_data(&data, arg_data, len);
	}

bool PendingDataInStream::Retry() const
	{
	return file_mgr->DataIn(data, len, tag, conn, is_orig);
	}

PendingDataInStream::~PendingDataInStream()
	{
	delete [] data;
	}

PendingGap::PendingGap(uint64 arg_offset, uint64 arg_len,
                       AnalyzerTag::Tag arg_tag, Connection* arg_conn,
                       bool arg_is_orig)
	: PendingFile(arg_conn, arg_is_orig, arg_tag), offset(arg_offset),
	  len(arg_len)
	{
	}

bool PendingGap::Retry() const
	{
	return file_mgr->Gap(offset, len, tag, conn, is_orig);
	}

PendingEOF::PendingEOF(Connection* arg_conn, bool arg_is_orig)
	: PendingFile(arg_conn, arg_is_orig)
	{
	}

bool PendingEOF::Retry() const
	{
	return file_mgr->EndOfFile(conn, is_orig);
	}

PendingSize::PendingSize(uint64 arg_size, AnalyzerTag::Tag arg_tag,
                         Connection* arg_conn, bool arg_is_orig)
	: PendingFile(arg_conn, arg_is_orig, arg_tag), size(arg_size)
	{
	}

bool PendingSize::Retry() const
	{
	return file_mgr->SetSize(size, tag, conn, is_orig);
	}
