// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_RPC_NFS_H
#define ANALYZER_PROTOCOL_RPC_NFS_H

#include "RPC.h"
#include "XDR.h"
#include "Event.h"

namespace analyzer { namespace rpc {

class NFS_Interp : public RPC_Interpreter {
public:
	NFS_Interp(analyzer::Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	int RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n);
	int RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
				const u_char*& buf, int& n, double start_time,
				double last_time, int reply_len);

	// Returns a new val_list that already has a conn_val, rpc_status and
	// nfs_status. These are the first parameters for each nfs_* event
	// ...
	val_list* event_common_vl(RPC_CallInfo *c, BifEnum::rpc_status rpc_status,
				BifEnum::NFS3::status_t nfs_status,
				double rep_start_time, double rep_last_time,
				int reply_len);

	// These methods parse the appropriate NFSv3 "type" out of buf. If
	// there are any errors (i.e., buffer to short, etc), buf will be set
	// to 0. However, the methods might still return an allocated Val * !
	// So, you might want to Unref() the Val if buf is 0. Method names
	// are based on the type names of RFC 1813.
	StringVal* nfs3_fh(const u_char*& buf, int& n);
	RecordVal* nfs3_fattr(const u_char*& buf, int& n);
	EnumVal* nfs3_ftype(const u_char*& buf, int& n);
	RecordVal* nfs3_wcc_attr(const u_char*& buf, int& n);
	RecordVal* nfs3_diropargs(const u_char*&buf, int &n);
	StringVal* nfs3_filename(const u_char*& buf, int& n);
	StringVal* nfs3_nfspath(const u_char*& buf, int& n)
		{
		return nfs3_filename(buf,n);
		}

	RecordVal* nfs3_post_op_attr(const u_char*&buf, int &n);	// Return 0 or an fattr
	RecordVal* nfs3_pre_op_attr(const u_char*&buf, int &n);	// Return 0 or an wcc_attr
	RecordVal* nfs3_lookup_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordVal* nfs3_readargs(const u_char*& buf, int& n);
	RecordVal* nfs3_read_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status, bro_uint_t offset);
	RecordVal* nfs3_readlink_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordVal* nfs3_writeargs(const u_char*& buf, int& n);
	EnumVal* nfs3_stable_how(const u_char*& buf, int& n);
	RecordVal* nfs3_write_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordVal* nfs3_newobj_reply(const u_char*& buf, int&n, BifEnum::NFS3::status_t status);
	RecordVal* nfs3_delobj_reply(const u_char*& buf, int& n);
	StringVal* nfs3_post_op_fh(const u_char*& buf, int& n);
	RecordVal* nfs3_readdirargs(bool isplus, const u_char*& buf, int&n);
	RecordVal* nfs3_readdir_reply(bool isplus, const u_char*& buf, int&n, BifEnum::NFS3::status_t status);

	// Consumes the file data in the RPC message. Depending on NFS::return_data* consts
	// in bro.init returns NULL or the data as string val:
	//   * offset is the offset of the read/write call
	//   * size is the amount of bytes read (or requested to be written),
	StringVal* nfs3_file_data(const u_char*& buf, int& n, uint64_t offset, int size);

	RecordVal* ExtractOptAttrs(const u_char*& buf, int& n);
	Val* ExtractUint32(const u_char*& buf, int& n);
	Val* ExtractUint64(const u_char*& buf, int& n);
	Val* ExtractTime(const u_char*& buf, int& n);
	Val* ExtractInterval(const u_char*& buf, int& n);
	Val* ExtractBool(const u_char*& buf, int& n);
};

class NFS_Analyzer : public RPC_Analyzer {
public:
	NFS_Analyzer(Connection* conn);
	virtual void Init();

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new NFS_Analyzer(conn); }
};


} } // namespace analyzer::* 

#endif
