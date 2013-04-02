#include <vector>
#include <string>

#include "Manager.h"
#include "Info.h"
#include "Action.h"
#include "Var.h"
#include "Event.h"

using namespace file_analysis;

TableVal* Manager::disabled = 0;

Manager::Manager()
	{
	}

Manager::~Manager()
	{
	Terminate();
	}

void Manager::Terminate()
	{
	vector<FileID> keys;
	for ( IDMap::iterator it = id_map.begin(); it != id_map.end(); ++it )
		keys.push_back(it->first);
	for ( size_t i = 0; i < keys.size(); ++i )
		Timeout(keys[i], true);
	}

void Manager::ReceiveHandle(const string& handle)
	{
	if ( pending.empty() )
		reporter->InternalError("File analysis underflow");

	int use_count = cache.front();
	cache.pop();

	for ( int i = 0; i < use_count; ++i )
		{
		PendingFile* pf = pending.front();
		if ( ! handle.empty() )
			pf->Finish(handle);
		delete pf;
		pending.pop();
		}
	}

void Manager::EventDrainDone()
	{
	if ( pending.empty() ) return;

	reporter->Error("Too few return_file_handle() calls, discarding pending"
	                " file analysis input.");

	while ( ! pending.empty() )
		{
		delete pending.front();
		pending.pop();
		}
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     AnalyzerTag::Tag tag, Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingDataInChunk(data, len, offset, tag, conn));
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     const string& unique)
	{
	DataIn(data, len, offset, GetInfo(unique));
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     Info* info)
	{
	if ( ! info ) return;

	info->DataIn(data, len, offset);

	if ( info->IsComplete() )
		RemoveFile(info->GetUnique());
	}

void Manager::DataIn(const u_char* data, uint64 len, AnalyzerTag::Tag tag,
                     Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingDataInStream(data, len, tag, conn));
	}

void Manager::DataIn(const u_char* data, uint64 len, const string& unique)
	{
	DataIn(data, len, GetInfo(unique));
	}

void Manager::DataIn(const u_char* data, uint64 len, Info* info)
	{
	if ( ! info ) return;

	info->DataIn(data, len);

	if ( info->IsComplete() )
		RemoveFile(info->GetUnique());
	}

void Manager::EndOfFile(AnalyzerTag::Tag tag, Connection* conn)
	{
	EndOfFile(tag, conn, true);
	EndOfFile(tag, conn, false);
	}

void Manager::EndOfFile(AnalyzerTag::Tag tag, Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingEOF(tag, conn));
	}

void Manager::EndOfFile(const string& unique)
	{
	RemoveFile(unique);
	}

void Manager::Gap(uint64 offset, uint64 len, AnalyzerTag::Tag tag,
                  Connection* conn, bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingGap(offset, len, tag, conn));
	}

void Manager::Gap(uint64 offset, uint64 len, const string& unique)
	{
	Gap(offset, len, GetInfo(unique));
	}

void Manager::Gap(uint64 offset, uint64 len, Info* info)
	{
	if ( ! info ) return;

	info->Gap(offset, len);
	}

void Manager::SetSize(uint64 size, AnalyzerTag::Tag tag, Connection* conn,
                      bool is_orig)
	{
	if ( IsDisabled(tag) ) return;
	if ( ! QueueHandleEvent(tag, conn, is_orig) ) return;
	pending.push(new PendingSize(size, tag, conn));
	}

void Manager::SetSize(uint64 size, const string& unique)
	{
	SetSize(size, GetInfo(unique));
	}

void Manager::SetSize(uint64 size, Info* info)
	{
	if ( ! info ) return;

	info->SetTotalBytes(size);

	if ( info->IsComplete() )
		RemoveFile(info->GetUnique());
	}

void Manager::EvaluatePolicy(BifEnum::FileAnalysis::Trigger t, Info* info)
	{
	if ( IsIgnored(info->GetUnique()) ) return;

	const ID* id = global_scope()->Lookup("FileAnalysis::policy");
	assert(id);
	const Func* hook = id->ID_Val()->AsFunc();

	val_list vl(2);
	vl.append(new EnumVal(t, BifType::Enum::FileAnalysis::Trigger));
	vl.append(info->val->Ref());

	info->postpone_timeout = false;

	Val* result = hook->Call(&vl);
	Unref(result);
	}

bool Manager::PostponeTimeout(const FileID& file_id) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	info->postpone_timeout = true;
	return true;
	}

bool Manager::AddAction(const FileID& file_id, RecordVal* args) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->AddAction(args);
	}

bool Manager::RemoveAction(const FileID& file_id, const RecordVal* args) const
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return false;

	return info->RemoveAction(args);
	}

Info* Manager::GetInfo(const string& unique, Connection* conn,
                       AnalyzerTag::Tag tag)
	{
	if ( IsIgnored(unique) ) return 0;

	Info* rval = str_map[unique];

	if ( ! rval )
		{
		rval = str_map[unique] = new Info(unique, conn, tag);
		FileID id = rval->GetFileID();

		if ( id_map[id] )
			{
			reporter->Error("Evicted duplicate file ID: %s", id.c_str());
			RemoveFile(unique);
			}

		id_map[id] = rval;
		file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_NEW, rval);
		rval->ScheduleInactivityTimer();
		if ( IsIgnored(unique) ) return 0;
		}
	else
		{
		rval->UpdateLastActivityTime();
		rval->UpdateConnectionFields(conn);
		}

	return rval;
	}

Info* Manager::Lookup(const FileID& file_id) const
	{
	IDMap::const_iterator it = id_map.find(file_id);

	if ( it == id_map.end() ) return 0;

	return it->second;
	}

void Manager::Timeout(const FileID& file_id, bool is_terminating)
	{
	Info* info = Lookup(file_id);

	if ( ! info ) return;

	file_mgr->EvaluatePolicy(BifEnum::FileAnalysis::TRIGGER_TIMEOUT, info);

	if ( info->postpone_timeout && ! is_terminating )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Postpone file analysis timeout for %s",
		        info->GetFileID().c_str());
		info->UpdateLastActivityTime();
		info->ScheduleInactivityTimer();
		return;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "File analysis timeout for %s",
	        info->GetFileID().c_str());

	RemoveFile(info->GetUnique());
	}

bool Manager::IgnoreFile(const FileID& file_id)
	{
	IDMap::iterator it = id_map.find(file_id);

	if ( it == id_map.end() ) return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Ignore FileID %s", file_id.c_str());

	ignored.insert(it->second->GetUnique());

	return true;
	}

bool Manager::RemoveFile(const string& unique)
	{
	StrMap::iterator it = str_map.find(unique);

	if ( it == str_map.end() ) return false;

	it->second->EndOfFile();

	FileID id = it->second->GetFileID();

	DBG_LOG(DBG_FILE_ANALYSIS, "Remove FileID %s", id.c_str());

	if ( ! id_map.erase(id) )
		reporter->Error("No mapping for fileID %s", id.c_str());

	ignored.erase(unique);
	delete it->second;
	str_map.erase(unique);
	return true;
	}

bool Manager::IsIgnored(const string& unique)
	{
	return ignored.find(unique) != ignored.end();
	}

bool Manager::IsDisabled(AnalyzerTag::Tag tag)
	{
	if ( ! disabled )
		disabled = internal_const_val("FileAnalysis::disable")->AsTableVal();

	Val* index = new Val(tag, TYPE_COUNT);
	Val* yield = disabled->Lookup(index);
	Unref(index);

	if ( ! yield ) return false;

	bool rval = yield->AsBool();
	Unref(yield);

	return rval;
	}

static bool CheckArgEquality(AnalyzerTag::Tag tag, Connection* conn,
                             bool is_orig, val_list* other_args)
	{
	if ( ! other_args ) return false;
	if ( (*other_args)[0]->AsCount() != (bro_uint_t) tag ) return false;
	if ( (*other_args)[2]->AsBool() != is_orig ) return false;

	RecordVal* id = (*other_args)[1]->AsRecordVal()->Lookup(
	        connection_type->FieldOffset("id"))->AsRecordVal();

	PortVal* orig_p = id->Lookup(
	        conn_id->FieldOffset("orig_p"))->AsPortVal();

	if ( orig_p->Port() != ntohs(conn->OrigPort()) ) return false;
	if ( orig_p->PortType() != conn->ConnTransport() ) return false;

	PortVal* resp_p = id->Lookup(
	        conn_id->FieldOffset("resp_p"))->AsPortVal();

	if ( resp_p->Port() != ntohs(conn->RespPort()) ) return false;

	if ( id->Lookup(conn_id->FieldOffset("orig_h"))->AsAddr() !=
	     conn->OrigAddr() ) return false;

	if ( id->Lookup(conn_id->FieldOffset("resp_h"))->AsAddr() !=
	     conn->RespAddr() ) return false;

	return true;
	}

bool Manager::QueueHandleEvent(AnalyzerTag::Tag tag, Connection* conn,
                               bool is_orig)
	{
	if ( ! get_file_handle ) return false;

	if ( mgr.Tail() == get_file_handle &&
	     CheckArgEquality(tag, conn, is_orig, mgr.TailArgs()) )
		{
		cache.front()++;
		return true;
		}

	cache.push(1);

	val_list* vl = new val_list();
	vl->append(new Val(tag, TYPE_COUNT));
	vl->append(conn->BuildConnVal());
	vl->append(new Val(is_orig, TYPE_BOOL));

	mgr.QueueEvent(get_file_handle, vl);
	return true;
	}
