// See the file "COPYING" in the main distribution directory for copyright.

#include "AnalyzerSet.h"
#include "File.h"
#include "Analyzer.h"
#include "Manager.h"

using namespace file_analysis;

static void analyzer_del_func(void* v)
	{
	delete (file_analysis::Analyzer*) v;
	}

AnalyzerSet::AnalyzerSet(File* arg_file) : file(arg_file)
	{
	TypeList* t = new TypeList();
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

bool AnalyzerSet::Add(RecordVal* args)
	{
	HashKey* key = GetKey(args);

	if ( analyzer_map.Lookup(key) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Instantiate analyzer %d skipped for file id"
		        " %s: already exists", file_analysis::Analyzer::ArgsTag(args),
		        file->GetID().c_str());
		delete key;
		return true;
		}

	file_analysis::Analyzer* a = InstantiateAnalyzer(args);

	if ( ! a )
		{
		delete key;
		return false;
		}

	Insert(a, key);

	return true;
	}

bool AnalyzerSet::QueueAdd(RecordVal* args)
	{
	HashKey* key = GetKey(args);
	file_analysis::Analyzer* a = InstantiateAnalyzer(args);

	if ( ! a )
		{
		delete key;
		return false;
		}

	mod_queue.push(new AddMod(a, key));

	return true;
	}

bool AnalyzerSet::AddMod::Perform(AnalyzerSet* set)
	{
	if ( set->analyzer_map.Lookup(key) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Add analyzer %d skipped for file id"
		        " %s: already exists", a->Tag(), a->GetFile()->GetID().c_str());

		Abort();
		return true;
		}

	set->Insert(a, key);
	return true;
	}

bool AnalyzerSet::Remove(const RecordVal* args)
	{
	return Remove(file_analysis::Analyzer::ArgsTag(args), GetKey(args));
	}

bool AnalyzerSet::Remove(FA_Tag tag, HashKey* key)
	{
	file_analysis::Analyzer* a =
	    (file_analysis::Analyzer*) analyzer_map.Remove(key);

	delete key;

	if ( ! a )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Skip remove analyzer %d for file id %s",
		        tag, file->GetID().c_str());
		return false;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "Remove analyzer %d for file id %s", a->Tag(),
	        file->GetID().c_str());

	delete a;
	return true;
	}

bool AnalyzerSet::QueueRemove(const RecordVal* args)
	{
	HashKey* key = GetKey(args);
	FA_Tag tag = file_analysis::Analyzer::ArgsTag(args);

	mod_queue.push(new RemoveMod(tag, key));

	return analyzer_map.Lookup(key);
	}

bool AnalyzerSet::RemoveMod::Perform(AnalyzerSet* set)
	{
	return set->Remove(tag, key);
	}

HashKey* AnalyzerSet::GetKey(const RecordVal* args) const
	{
	HashKey* key = analyzer_hash->ComputeHash(args, 1);
	if ( ! key )
		reporter->InternalError("AnalyzerArgs type mismatch");

	return key;
	}

file_analysis::Analyzer* AnalyzerSet::InstantiateAnalyzer(RecordVal* args) const
	{
	FA_Tag tag = file_analysis::Analyzer::ArgsTag(args);
	file_analysis::Analyzer* a = file_mgr->InstantiateAnalyzer(tag, args, file);

	if ( ! a )
		{
		reporter->Error("Failed file analyzer %s instantiation for file id %s",
		                file_mgr->GetAnalyzerName(tag), file->GetID().c_str());
		return 0;
		}

	return a;
	}

void AnalyzerSet::Insert(file_analysis::Analyzer* a, HashKey* key)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Add analyzer %d for file id %s", a->Tag(),
	        file->GetID().c_str());
	analyzer_map.Insert(key, a);
	delete key;
	}

void AnalyzerSet::DrainModifications()
	{
	if ( mod_queue.empty() )
		return;

	DBG_LOG(DBG_FILE_ANALYSIS, "Start analyzer mod queue flush of file id %s",
	        file->GetID().c_str());
	do
		{
		Modification* mod = mod_queue.front();
		mod->Perform(this);
		delete mod;
		mod_queue.pop();
		} while ( ! mod_queue.empty() );
	DBG_LOG(DBG_FILE_ANALYSIS, "End flushing analyzer mod queue of file id %s",
	        file->GetID().c_str());
	}
