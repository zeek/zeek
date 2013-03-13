#include <vector>
#include <string>

#include "Manager.h"
#include "Info.h"
#include "Action.h"
#include "Var.h"

using namespace file_analysis;

Manager::Manager()
	{
	}

Manager::~Manager()
	{
	Terminate();
	}

string Manager::GetFileHandle(Analyzer* root, Connection* conn,
                              bool is_orig) const
	{
	static TableVal* table = 0;

	if ( ! table )
		table = internal_val("FileAnalysis::handle_callbacks")->AsTableVal();

	if ( ! root ) return "";

	Val* index = new Val(root->GetTag(), TYPE_COUNT);
	const Val* callback = table->Lookup(index);
	Unref(index);

	if ( callback )
		{
		val_list vl(2);
		vl.append(conn->BuildConnVal());
		vl.append(new Val(is_orig, TYPE_BOOL));

		Val* result = callback->AsFunc()->Call(&vl);
		string rval = result->AsString()->CheckString();
		Unref(result);

		if ( ! rval.empty() ) return rval;
		}

	for ( analyzer_list::const_iterator	it = root->GetChildren().begin();
	      it != root->GetChildren().end(); ++it )
		{
		string rval = GetFileHandle((*it), conn, is_orig);
		if ( ! rval.empty() ) return rval;
		}

	return "";
	}

string Manager::GetFileHandle(Connection* conn, bool is_orig) const
	{
	if ( ! conn ) return "";

	return GetFileHandle(conn->GetRootAnalyzer(), conn, is_orig);
	}

void Manager::DrainPending()
	{
	for ( size_t i = 0; i < pending.size(); ++i )
		pending[i].Retry();

	pending.clear();
	}

void Manager::Terminate()
	{
	vector<FileID> keys;
	for ( IDMap::iterator it = id_map.begin(); it != id_map.end(); ++it )
		keys.push_back(it->first);
	for ( size_t i = 0; i < keys.size(); ++i )
		Timeout(keys[i], true);
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     Connection* conn, bool is_orig, bool allow_retry)
	{
	string unique = GetFileHandle(conn, is_orig);

	if ( ! unique.empty() )
		{
		DataIn(data, len, offset, GetInfo(unique, conn));
		return;
		}

	if ( allow_retry )
		pending.push_back(PendingFile(data, len, offset, conn, is_orig));
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

void Manager::DataIn(const u_char* data, uint64 len, Connection* conn,
                     bool is_orig, bool allow_retry)
	{
	string unique = GetFileHandle(conn, is_orig);

	if ( ! unique.empty() )
		{
		DataIn(data, len, GetInfo(unique, conn));
		return;
		}

	if ( allow_retry )
		pending.push_back(PendingFile(data, len, conn, is_orig));
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

void Manager::EndOfFile(Connection* conn)
	{
	EndOfFile(conn, true);
	EndOfFile(conn, false);
	}

void Manager::EndOfFile(Connection* conn, bool is_orig)
	{
	string unique = GetFileHandle(conn, is_orig);

	if ( unique.empty() ) return; // nothing to do

	RemoveFile(unique);
	}

void Manager::EndOfFile(const string& unique)
	{
	RemoveFile(unique);
	}

void Manager::Gap(uint64 offset, uint64 len, Connection* conn, bool is_orig)
	{
	string unique = GetFileHandle(conn, is_orig);

	if ( unique.empty() ) return;  // nothing to do since no data has been seen

	Gap(offset, len, GetInfo(unique, conn));
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

void Manager::SetSize(uint64 size, Connection* conn, bool is_orig)
	{
	string unique = GetFileHandle(conn, is_orig);

	if ( unique.empty() ) return; // ok assuming this always follows a DataIn()

	SetSize(size, GetInfo(unique, conn));
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

Info* Manager::GetInfo(const string& unique, Connection* conn)
	{
	if ( IsIgnored(unique) ) return 0;

	Info* rval = str_map[unique];

	if ( ! rval )
		{
		rval = str_map[unique] = new Info(unique, conn);
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
	str_map.erase(unique);
	delete it->second;
	return true;
	}

bool Manager::IsIgnored(const string& unique)
	{
	return ignored.find(unique) != ignored.end();
	}
