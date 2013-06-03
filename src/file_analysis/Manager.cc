// See the file "COPYING" in the main distribution directory for copyright.

#include <vector>
#include <string>
#include <openssl/md5.h>

#include "Manager.h"
#include "File.h"
#include "Analyzer.h"
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
	vector<string> keys;
	for ( IDMap::iterator it = id_map.begin(); it != id_map.end(); ++it )
		keys.push_back(it->first);

	for ( size_t i = 0; i < keys.size(); ++i )
		Timeout(keys[i], true);
	}

string Manager::HashHandle(const string& handle) const
	{
	static string salt;

	if ( salt.empty() )
		salt = BifConst::FileAnalysis::salt->CheckString();

	char tmp[20];
	uint64 hash[2];
	string msg(handle + salt);

	MD5(reinterpret_cast<const u_char*>(msg.data()), msg.size(),
	    reinterpret_cast<u_char*>(hash));
	uitoa_n(hash[0], tmp, sizeof(tmp), 62);

	return tmp;
	}

void Manager::SetHandle(const string& handle)
	{
	if ( handle.empty() )
		return;

	current_file_id = HashHandle(handle);
	}

void Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                     AnalyzerTag::Tag tag, Connection* conn, bool is_orig)
	{
	GetFileHandle(tag, conn, is_orig);
	File* file = GetFile(current_file_id, conn, tag, is_orig);

	if ( ! file )
		return;

	file->DataIn(data, len, offset);

	if ( file->IsComplete() )
		RemoveFile(file->GetID());
	}

void Manager::DataIn(const u_char* data, uint64 len, AnalyzerTag::Tag tag,
                     Connection* conn, bool is_orig)
	{
	GetFileHandle(tag, conn, is_orig);
	// Sequential data input shouldn't be going over multiple conns, so don't
	// do the check to update connection set.
	File* file = GetFile(current_file_id, conn, tag, is_orig, false);

	if ( ! file )
		return;

	file->DataIn(data, len);

	if ( file->IsComplete() )
		RemoveFile(file->GetID());
	}

void Manager::DataIn(const u_char* data, uint64 len, const string& file_id,
                     const string& source)
	{
	File* file = GetFile(file_id);

	if ( ! file )
		return;

	if ( file->GetSource().empty() )
		file->SetSource(source);

	file->DataIn(data, len);

	if ( file->IsComplete() )
		RemoveFile(file->GetID());
	}

void Manager::EndOfFile(AnalyzerTag::Tag tag, Connection* conn)
	{
	EndOfFile(tag, conn, true);
	EndOfFile(tag, conn, false);
	}

void Manager::EndOfFile(AnalyzerTag::Tag tag, Connection* conn, bool is_orig)
	{
	// Don't need to create a file if we're just going to remove it right away.
	GetFileHandle(tag, conn, is_orig);
	RemoveFile(current_file_id);
	}

void Manager::EndOfFile(const string& file_id)
	{
	RemoveFile(file_id);
	}

void Manager::Gap(uint64 offset, uint64 len, AnalyzerTag::Tag tag,
                  Connection* conn, bool is_orig)
	{
	GetFileHandle(tag, conn, is_orig);
	File* file = GetFile(current_file_id, conn, tag, is_orig);

	if ( ! file )
		return;

	file->Gap(offset, len);
	}

void Manager::SetSize(uint64 size, AnalyzerTag::Tag tag, Connection* conn,
                      bool is_orig)
	{
	GetFileHandle(tag, conn, is_orig);
	File* file = GetFile(current_file_id, conn, tag, is_orig);

	if ( ! file )
		return;

	file->SetTotalBytes(size);

	if ( file->IsComplete() )
		RemoveFile(file->GetID());
	}

bool Manager::SetTimeoutInterval(const string& file_id, double interval) const
	{
	File* file = Lookup(file_id);

	if ( ! file )
		return false;

	if ( interval > 0 )
		file->postpone_timeout = true;

	file->SetTimeoutInterval(interval);
	return true;
	}

bool Manager::AddAnalyzer(const string& file_id, RecordVal* args) const
	{
	File* file = Lookup(file_id);

	if ( ! file )
		return false;

	return file->AddAnalyzer(args);
	}

bool Manager::RemoveAnalyzer(const string& file_id, const RecordVal* args) const
	{
	File* file = Lookup(file_id);

	if ( ! file )
		return false;

	return file->RemoveAnalyzer(args);
	}

File* Manager::GetFile(const string& file_id, Connection* conn,
                       AnalyzerTag::Tag tag, bool is_orig, bool update_conn)
	{
	if ( file_id.empty() )
		return 0;

	if ( IsIgnored(file_id) )
		return 0;

	File* rval = id_map[file_id];

	if ( ! rval )
		{
		rval = id_map[file_id] = new File(file_id, conn, tag, is_orig);
		rval->ScheduleInactivityTimer();

		if ( IsIgnored(file_id) )
			return 0;
		}
	else
		{
		rval->UpdateLastActivityTime();

		if ( update_conn )
			rval->UpdateConnectionFields(conn);
		}

	return rval;
	}

File* Manager::Lookup(const string& file_id) const
	{
	IDMap::const_iterator it = id_map.find(file_id);

	if ( it == id_map.end() )
		return 0;

	return it->second;
	}

void Manager::Timeout(const string& file_id, bool is_terminating)
	{
	File* file = Lookup(file_id);

	if ( ! file )
		return;

	file->postpone_timeout = false;

	file->FileEvent(file_timeout);

	if ( file->postpone_timeout && ! is_terminating )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Postpone file analysis timeout for %s",
		        file->GetID().c_str());
		file->UpdateLastActivityTime();
		file->ScheduleInactivityTimer();
		return;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "File analysis timeout for %s",
	        file->GetID().c_str());

	RemoveFile(file->GetID());
	}

bool Manager::IgnoreFile(const string& file_id)
	{
	if ( id_map.find(file_id) == id_map.end() )
		return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Ignore FileID %s", file_id.c_str());

	ignored.insert(file_id);

	return true;
	}

bool Manager::RemoveFile(const string& file_id)
	{
	IDMap::iterator it = id_map.find(file_id);

	if ( it == id_map.end() )
		return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Remove FileID %s", file_id.c_str());

	it->second->EndOfFile();

	delete it->second;
	id_map.erase(file_id);
	ignored.erase(file_id);

	return true;
	}

bool Manager::IsIgnored(const string& file_id)
	{
	return ignored.find(file_id) != ignored.end();
	}

void Manager::GetFileHandle(AnalyzerTag::Tag tag, Connection* c, bool is_orig)
	{
	current_file_id.clear();

	if ( IsDisabled(tag) )
		return;

	if ( ! get_file_handle )
		return;

	val_list* vl = new val_list();
	vl->append(new Val(tag, TYPE_COUNT));
	vl->append(c->BuildConnVal());
	vl->append(new Val(is_orig, TYPE_BOOL));

	mgr.QueueEvent(get_file_handle, vl);
	mgr.Drain(); // need file handle immediately so we don't have to buffer data
	}

bool Manager::IsDisabled(AnalyzerTag::Tag tag)
	{
	if ( ! disabled )
		disabled = internal_const_val("FileAnalysis::disable")->AsTableVal();

	Val* index = new Val(tag, TYPE_COUNT);
	Val* yield = disabled->Lookup(index);
	Unref(index);

	if ( ! yield )
		return false;

	bool rval = yield->AsBool();
	Unref(yield);

	return rval;
	}
