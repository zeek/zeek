// See the file "COPYING" in the main distribution directory for copyright.

#include "AnalyzerSet.h"
#include "File.h"
#include "Analyzer.h"
#include "Manager.h"

using namespace file_analysis;

static void analyzer_del_func(void* v)
	{
	file_analysis::Analyzer* a = (file_analysis::Analyzer*)v;

	a->Done();
	delete a;
	}

AnalyzerSet::AnalyzerSet(File* arg_file) : file(arg_file)
	{
	TypeList* t = new TypeList();
	t->Append(file_mgr->GetTagEnumType()->Ref());
	t->Append(BifType::Record::Files::AnalyzerArgs->Ref());
	analyzer_hash = new CompositeHash(t);
	Unref(t);
	analyzer_map.SetDeleteFunc(analyzer_del_func);
	}

AnalyzerSet::~AnalyzerSet()
	{
	while ( ! mod_queue.empty() )
		{
		Modification* mod = mod_queue.front();
		mod->Abort();
		delete mod;
		mod_queue.pop();
		}

	delete analyzer_hash;
	}

Analyzer* AnalyzerSet::Find(const file_analysis::Tag& tag, RecordVal* args)
	{
	HashKey* key = GetKey(tag, args);
	Analyzer* rval = analyzer_map.Lookup(key);
	delete key;
	return rval;
	}

bool AnalyzerSet::Add(const file_analysis::Tag& tag, RecordVal* args)
	{
	HashKey* key = GetKey(tag, args);

	if ( analyzer_map.Lookup(key) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Instantiate analyzer %s skipped: already exists",
		        file->GetID().c_str(),
		        file_mgr->GetComponentName(tag).c_str());

		delete key;
		return true;
		}

	file_analysis::Analyzer* a = InstantiateAnalyzer(tag, args);

	if ( ! a )
		{
		delete key;
		return false;
		}

	Insert(a, key);

	return true;
	}

Analyzer* AnalyzerSet::QueueAdd(const file_analysis::Tag& tag, RecordVal* args)
	{
	HashKey* key = GetKey(tag, args);
	file_analysis::Analyzer* a = InstantiateAnalyzer(tag, args);

	if ( ! a )
		{
		delete key;
		return 0;
		}

	mod_queue.push(new AddMod(a, key));

	return a;
	}

bool AnalyzerSet::AddMod::Perform(AnalyzerSet* set)
	{
	if ( set->analyzer_map.Lookup(key) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Add analyzer %s skipped: already exists",
		        a->GetFile()->GetID().c_str(),
		        file_mgr->GetComponentName(a->Tag()).c_str());

		Abort();
		return true;
		}

	set->Insert(a, key);

	return true;
	}

bool AnalyzerSet::Remove(const file_analysis::Tag& tag, RecordVal* args)
	{
	return Remove(tag, GetKey(tag, args));
	}

bool AnalyzerSet::Remove(const file_analysis::Tag& tag, HashKey* key)
	{
	file_analysis::Analyzer* a =
	    (file_analysis::Analyzer*) analyzer_map.Remove(key);

	delete key;

	if ( ! a )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Skip remove analyzer %s",
		        file->GetID().c_str(), file_mgr->GetComponentName(tag).c_str());
		return false;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Remove analyzer %s",
	        file->GetID().c_str(),
	        file_mgr->GetComponentName(tag).c_str());

	a->Done();

	// We don't delete the analyzer object right here because the remove
	// operation may execute at a time when it can still be accessed.
	// Instead we let the file know to delete the analyzer later.
	file->DoneWithAnalyzer(a);

	return true;
	}

bool AnalyzerSet::QueueRemove(const file_analysis::Tag& tag, RecordVal* args)
	{
	HashKey* key = GetKey(tag, args);

	mod_queue.push(new RemoveMod(tag, key));

	return analyzer_map.Lookup(key);
	}

bool AnalyzerSet::RemoveMod::Perform(AnalyzerSet* set)
	{
	return set->Remove(tag, key);
	}

HashKey* AnalyzerSet::GetKey(const file_analysis::Tag& t, RecordVal* args) const
	{
	ListVal* lv = new ListVal(TYPE_ANY);
	lv->Append(t.AsEnumVal()->Ref());
	lv->Append(args->Ref());
	HashKey* key = analyzer_hash->ComputeHash(lv, 1);
	Unref(lv);
	if ( ! key )
		reporter->InternalError("AnalyzerArgs type mismatch");

	return key;
	}

file_analysis::Analyzer* AnalyzerSet::InstantiateAnalyzer(const Tag& tag,
                                                          RecordVal* args) const
	{
	file_analysis::Analyzer* a = file_mgr->InstantiateAnalyzer(tag, args, file);

	if ( ! a )
		{
		reporter->Error("[%s] Failed file analyzer %s instantiation",
		                file->GetID().c_str(),
		                file_mgr->GetComponentName(tag).c_str());
		return 0;
		}

	return a;
	}

void AnalyzerSet::Insert(file_analysis::Analyzer* a, HashKey* key)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Add analyzer %s",
	        file->GetID().c_str(), file_mgr->GetComponentName(a->Tag()).c_str());
	analyzer_map.Insert(key, a);
	delete key;

	a->Init();
	}

void AnalyzerSet::DrainModifications()
	{
	if ( mod_queue.empty() )
		return;

	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] Start analyzer mod queue flush",
	        file->GetID().c_str());
	do
		{
		Modification* mod = mod_queue.front();
		mod->Perform(this);
		delete mod;
		mod_queue.pop();
		} while ( ! mod_queue.empty() );
	DBG_LOG(DBG_FILE_ANALYSIS, "[%s] End flushing analyzer mod queue.",
	        file->GetID().c_str());
	}
