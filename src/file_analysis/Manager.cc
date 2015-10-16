// See the file "COPYING" in the main distribution directory for copyright.

#include <vector>
#include <string>
#include <openssl/md5.h>

#include "Manager.h"
#include "File.h"
#include "Analyzer.h"
#include "Var.h"
#include "Event.h"
#include "UID.h"

#include "plugin/Manager.h"
#include "analyzer/Manager.h"

using namespace file_analysis;

TableVal* Manager::disabled = 0;
TableType* Manager::tag_set_type = 0;
string Manager::salt;

Manager::Manager()
	: plugin::ComponentManager<file_analysis::Tag,
	                           file_analysis::Component>("Files", "Tag"),
	id_map(), ignored(), current_file_id(), magic_state()
	{
	}

Manager::~Manager()
	{
	for ( MIMEMap::iterator i = mime_types.begin(); i != mime_types.end(); i++ )
		delete i->second;

	// Have to assume that too much of Bro has been shutdown by this point
	// to do anything more than reclaim memory.

	File* f;
	bool* b;

	IterCookie* it = id_map.InitForIteration();

	while ( (f = id_map.NextEntry(it)) )
		delete f;

	it = ignored.InitForIteration();

	while( (b = ignored.NextEntry(it)) )
		delete b;

	delete magic_state;
	}

void Manager::InitPreScript()
	{
	}

void Manager::InitPostScript()
	{
	}

void Manager::InitMagic()
	{
	delete magic_state;
	magic_state = rule_matcher->InitFileMagic();
	}

void Manager::Terminate()
	{
	vector<string> keys;

	IterCookie* it = id_map.InitForIteration();
	HashKey* key;

	while ( id_map.NextEntry(key, it) )
		{
		keys.push_back(string(static_cast<const char*>(key->Key()),
		                      key->Size()));
		delete key;
		}

	for ( size_t i = 0; i < keys.size(); ++i )
		Timeout(keys[i], true);

	mgr.Drain();
	}

string Manager::HashHandle(const string& handle) const
	{
	if ( salt.empty() )
		salt = BifConst::Files::salt->CheckString();

	uint64 hash[2];
	string msg(handle + salt);

	MD5(reinterpret_cast<const u_char*>(msg.data()), msg.size(),
	    reinterpret_cast<u_char*>(hash));

	return Bro::UID(bits_per_uid, hash, 2).Base62("F");
	}

void Manager::SetHandle(const string& handle)
	{
	if ( handle.empty() )
		return;

	DBG_LOG(DBG_FILE_ANALYSIS, "Set current handle to %s", handle.c_str());
	current_file_id = HashHandle(handle);
	}

string Manager::DataIn(const u_char* data, uint64 len, uint64 offset,
                       analyzer::Tag tag, Connection* conn, bool is_orig,
                       const string& precomputed_id)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	File* file = GetFile(id, conn, tag, is_orig);

	if ( ! file )
		return "";

	file->DataIn(data, len, offset);

	if ( file->IsComplete() )
		{
		RemoveFile(file->GetID());
		return "";
		}

	return id;
	}

string Manager::DataIn(const u_char* data, uint64 len, analyzer::Tag tag,
                       Connection* conn, bool is_orig, const string& precomputed_id)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	// Sequential data input shouldn't be going over multiple conns, so don't
	// do the check to update connection set.
	File* file = GetFile(id, conn, tag, is_orig, false);

	if ( ! file )
		return "";

	file->DataIn(data, len);

	if ( file->IsComplete() )
		{
		RemoveFile(file->GetID());
		return "";
		}

	return id;
	}

void Manager::DataIn(const u_char* data, uint64 len, const string& file_id,
                     const string& source)
	{
	File* file = GetFile(file_id, 0, analyzer::Tag::Error, false, false,
	                     source.c_str());

	if ( ! file )
		return;

	file->DataIn(data, len);

	if ( file->IsComplete() )
		RemoveFile(file->GetID());
	}

void Manager::EndOfFile(analyzer::Tag tag, Connection* conn)
	{
	EndOfFile(tag, conn, true);
	EndOfFile(tag, conn, false);
	}

void Manager::EndOfFile(analyzer::Tag tag, Connection* conn, bool is_orig)
	{
	// Don't need to create a file if we're just going to remove it right away.
	RemoveFile(GetFileID(tag, conn, is_orig));
	}

void Manager::EndOfFile(const string& file_id)
	{
	RemoveFile(file_id);
	}

string Manager::Gap(uint64 offset, uint64 len, analyzer::Tag tag,
                    Connection* conn, bool is_orig, const string& precomputed_id)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	File* file = GetFile(id, conn, tag, is_orig);

	if ( ! file )
		return "";

	file->Gap(offset, len);
	return id;
	}

string Manager::SetSize(uint64 size, analyzer::Tag tag, Connection* conn,
                        bool is_orig, const string& precomputed_id)
	{
	string id = precomputed_id.empty() ? GetFileID(tag, conn, is_orig) : precomputed_id;
	File* file = GetFile(id, conn, tag, is_orig);

	if ( ! file )
		return "";

	file->SetTotalBytes(size);

	if ( file->IsComplete() )
		{
		RemoveFile(file->GetID());
		return "";
		}

	return id;
	}

bool Manager::SetTimeoutInterval(const string& file_id, double interval) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	if ( interval > 0 )
		file->postpone_timeout = true;

	file->SetTimeoutInterval(interval);
	return true;
	}

bool Manager::EnableReassembly(const string& file_id)
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	file->EnableReassembly();
	return true;
	}

bool Manager::DisableReassembly(const string& file_id)
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	file->DisableReassembly();
	return true;
	}

bool Manager::SetReassemblyBuffer(const string& file_id, uint64 max)
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	file->SetReassemblyBuffer(max);
	return true;
	}

bool Manager::SetExtractionLimit(const string& file_id, RecordVal* args,
                                 uint64 n) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	return file->SetExtractionLimit(args, n);
	}

bool Manager::AddAnalyzer(const string& file_id, file_analysis::Tag tag,
                          RecordVal* args) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	return file->AddAnalyzer(tag, args);
	}

bool Manager::RemoveAnalyzer(const string& file_id, file_analysis::Tag tag,
                             RecordVal* args) const
	{
	File* file = LookupFile(file_id);

	if ( ! file )
		return false;

	return file->RemoveAnalyzer(tag, args);
	}

File* Manager::GetFile(const string& file_id, Connection* conn,
                       analyzer::Tag tag, bool is_orig, bool update_conn,
                       const char* source_name)
	{
	if ( file_id.empty() )
		return 0;

	if ( IsIgnored(file_id) )
		return 0;

	File* rval = id_map.Lookup(file_id.c_str());

	if ( ! rval )
		{
		rval = new File(file_id,
		                source_name ? source_name
		                            : analyzer_mgr->GetComponentName(tag),
		                conn, tag, is_orig);
		id_map.Insert(file_id.c_str(), rval);
		rval->ScheduleInactivityTimer();

		// Generate file_new after inserting it into manager's mapping
		// in case script-layer calls back in to core from the event.
		rval->FileEvent(file_new);
		// Same for file_over_new_connection.
		rval->RaiseFileOverNewConnection(conn, is_orig);

		if ( IsIgnored(file_id) )
			return 0;
		}
	else
		{
		rval->UpdateLastActivityTime();

		if ( update_conn && rval->UpdateConnectionFields(conn, is_orig) )
			rval->RaiseFileOverNewConnection(conn, is_orig);
		}

	return rval;
	}

File* Manager::LookupFile(const string& file_id) const
	{
	return id_map.Lookup(file_id.c_str());
	}

void Manager::Timeout(const string& file_id, bool is_terminating)
	{
	File* file = LookupFile(file_id);

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
	if ( ! id_map.Lookup(file_id.c_str()) )
		return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "Ignore FileID %s", file_id.c_str());

	delete ignored.Insert(file_id.c_str(), new bool);
	return true;
	}

bool Manager::RemoveFile(const string& file_id)
	{
	HashKey key(file_id.c_str());
	// Can't remove from the dictionary/map right away as invoking EndOfFile
	// may cause some events to be executed which actually depend on the file
	// still being in the dictionary/map.
	File* f = static_cast<File*>(id_map.Lookup(&key));

	if ( ! f )
		return false;

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Remove file", file_id.c_str());

	f->EndOfFile();
	delete f;
	id_map.Remove(&key);
	delete static_cast<bool*>(ignored.Remove(&key));
	return true;
	}

bool Manager::IsIgnored(const string& file_id)
	{
	return ignored.Lookup(file_id.c_str()) != 0;
	}

string Manager::GetFileID(analyzer::Tag tag, Connection* c, bool is_orig)
	{
	current_file_id.clear();

	if ( IsDisabled(tag) )
		return "";

	if ( ! get_file_handle )
		return "";

	DBG_LOG(DBG_FILE_ANALYSIS, "Raise get_file_handle() for protocol analyzer %s",
		analyzer_mgr->GetComponentName(tag).c_str());

	EnumVal* tagval = tag.AsEnumVal();
	Ref(tagval);

	val_list* vl = new val_list();
	vl->append(tagval);
	vl->append(c->BuildConnVal());
	vl->append(new Val(is_orig, TYPE_BOOL));

	mgr.QueueEvent(get_file_handle, vl);
	mgr.Drain(); // need file handle immediately so we don't have to buffer data
	return current_file_id;
	}

bool Manager::IsDisabled(analyzer::Tag tag)
	{
	if ( ! disabled )
		disabled = internal_const_val("Files::disable")->AsTableVal();

	Val* index = new Val(tag, TYPE_COUNT);
	Val* yield = disabled->Lookup(index);
	Unref(index);

	if ( ! yield )
		return false;

	bool rval = yield->AsBool();
	Unref(yield);

	return rval;
	}

Analyzer* Manager::InstantiateAnalyzer(Tag tag, RecordVal* args, File* f) const
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->InternalWarning(
		            "unknown file analyzer instantiation request: %s",
		            tag.AsString().c_str());
		return 0;
		}

	if ( ! c->Factory() )
		{
		reporter->InternalWarning("file analyzer %s cannot be instantiated "
					  "dynamically", c->CanonicalName().c_str());
		return 0;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Instantiate analyzer %s",
		f->id.c_str(), GetComponentName(tag).c_str());

	Analyzer* a = c->Factory()(args, f);

	if ( ! a )
		reporter->InternalError("file analyzer instantiation failed");

	a->SetAnalyzerTag(tag);

	return a;
	}

RuleMatcher::MIME_Matches* Manager::DetectMIME(const u_char* data, uint64 len,
        RuleMatcher::MIME_Matches* rval) const
	{
	if ( ! magic_state )
		reporter->InternalError("file magic signature state not initialized");

	rval = rule_matcher->Match(magic_state, data, len, rval);
	rule_matcher->ClearFileMagicState(magic_state);
	return rval;
	}

string Manager::DetectMIME(const u_char* data, uint64 len) const
	{
	RuleMatcher::MIME_Matches matches;
	DetectMIME(data, len, &matches);

	if ( matches.empty() )
		return "";

	return *(matches.begin()->second.begin());
	}

VectorVal* file_analysis::GenMIMEMatchesVal(const RuleMatcher::MIME_Matches& m)
	{
	VectorVal* rval = new VectorVal(mime_matches);

	for ( RuleMatcher::MIME_Matches::const_iterator it = m.begin();
	      it != m.end(); ++it )
		{
		RecordVal* element = new RecordVal(mime_match);

		for ( set<string>::const_iterator it2 = it->second.begin();
		      it2 != it->second.end(); ++it2 )
			{
			element->Assign(0, new Val(it->first, TYPE_INT));
			element->Assign(1, new StringVal(*it2));
			}

		rval->Assign(rval->Size(), element);
		}

	return rval;
	}
