#include "ActionSet.h"
#include "Info.h"
#include "Action.h"
#include "Extract.h"
#include "DataEvent.h"
#include "Hash.h"

using namespace file_analysis;

// keep in order w/ declared enum values in file_analysis.bif
static ActionInstantiator action_factory[] = {
	Extract::Instantiate,
	MD5::Instantiate,
	SHA1::Instantiate,
	SHA256::Instantiate,
	DataEvent::Instantiate,
};

static void action_del_func(void* v)
	{
	delete (Action*) v;
	}

ActionSet::ActionSet(Info* arg_info) : info(arg_info)
	{
	TypeList* t = new TypeList();
	t->Append(BifType::Record::FileAnalysis::ActionArgs->Ref());
	action_hash = new CompositeHash(t);
	Unref(t);
	action_map.SetDeleteFunc(action_del_func);
	}

ActionSet::~ActionSet()
	{
	while ( ! mod_queue.empty() )
		{
		Modification* mod = mod_queue.front();
		mod->Abort();
		delete mod;
		mod_queue.pop();
		}
	delete action_hash;
	}

bool ActionSet::AddAction(RecordVal* args)
	{
	HashKey* key = GetKey(args);

	if ( action_map.Lookup(key) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Instantiate action %d skipped for file id"
		        " %s: already exists", Action::ArgsTag(args),
		        info->GetFileID().c_str());
		delete key;
		return true;
		}

	Action* act = InstantiateAction(args);

	if ( ! act )
		{
		delete key;
		return false;
		}

	InsertAction(act, key);

	return true;
	}

bool ActionSet::QueueAddAction(RecordVal* args)
	{
	HashKey* key = GetKey(args);
	Action* act = InstantiateAction(args);

	if ( ! act )
		{
		delete key;
		return false;
		}

	mod_queue.push(new Add(act, key));

	return true;
	}

bool ActionSet::Add::Perform(ActionSet* set)
	{
	if ( set->action_map.Lookup(key) )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Add action %d skipped for file id"
		        " %s: already exists", act->Tag(),
		        act->GetInfo()->GetFileID().c_str());
		Abort();
		return true;
		}

	set->InsertAction(act, key);
	return true;
	}

bool ActionSet::RemoveAction(const RecordVal* args)
	{
	return RemoveAction(Action::ArgsTag(args), GetKey(args));
	}

bool ActionSet::RemoveAction(ActionTag tag, HashKey* key)
	{
	Action* act = (Action*) action_map.Remove(key);
	delete key;

	if ( ! act )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Skip remove action %d for file id %s",
		        tag, info->GetFileID().c_str());
		return false;
		}

	DBG_LOG(DBG_FILE_ANALYSIS, "Remove action %d for file id %s", act->Tag(),
	        info->GetFileID().c_str());
	delete act;
	return true;
	}

bool ActionSet::QueueRemoveAction(const RecordVal* args)
	{
	HashKey* key = GetKey(args);
	ActionTag tag = Action::ArgsTag(args);

	mod_queue.push(new Remove(tag, key));

	return action_map.Lookup(key);
	}

bool ActionSet::Remove::Perform(ActionSet* set)
	{
	return set->RemoveAction(tag, key);
	}

HashKey* ActionSet::GetKey(const RecordVal* args) const
	{
	HashKey* key = action_hash->ComputeHash(args, 1);
	if ( ! key )
		reporter->InternalError("ActionArgs type mismatch");
	return key;
	}

Action* ActionSet::InstantiateAction(RecordVal* args) const
	{
	Action* act = action_factory[Action::ArgsTag(args)](args, info);

	if ( ! act )
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Instantiate action %d failed for file id",
		        " %s", Action::ArgsTag(args), info->GetFileID().c_str());
		return 0;
		}

	return act;
	}

void ActionSet::InsertAction(Action* act, HashKey* key)
	{
	DBG_LOG(DBG_FILE_ANALYSIS, "Add action %d for file id %s", act->Tag(),
	        info->GetFileID().c_str());
	action_map.Insert(key, act);
	delete key;
	info->GetVal()->Lookup(Info::actions_idx)->AsTableVal()->Assign(act->Args(),
	        new RecordVal(BifType::Record::FileAnalysis::ActionResults));
	}

void ActionSet::DrainModifications()
	{
	if ( mod_queue.empty() ) return;

	DBG_LOG(DBG_FILE_ANALYSIS, "Start flushing action mod queue of file id %s",
	        info->GetFileID().c_str());
	do
		{
		Modification* mod = mod_queue.front();
		mod->Perform(this);
		delete mod;
		mod_queue.pop();
		} while ( ! mod_queue.empty() );
	DBG_LOG(DBG_FILE_ANALYSIS, "End flushing action mod queue of file id %s",
	        info->GetFileID().c_str());
	}
