#ifndef FILE_ANALYSIS_ACTION_H
#define FILE_ANALYSIS_ACTION_H

#include "Val.h"
#include "NetVar.h"

namespace file_analysis {

typedef BifEnum::FileAnalysis::Action ActionTag;

class File;

/**
 * Base class for actions that can be attached to a file_analysis::File object.
 */
class Action {
public:

	virtual ~Action()
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Destroy action %d", tag);
		Unref(args);
		}

	/**
	 * Subclasses may override this to receive file data non-sequentially.
	 * @return true if the action is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset)
		{ return true; }

	/**
	 * Subclasses may override this to receive file sequentially.
	 * @return true if the action is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool DeliverStream(const u_char* data, uint64 len)
		{ return true; }

	/**
	 * Subclasses may override this to specifically handle an EOF signal,
	 * which means no more data is going to be incoming and the action/analyzer
	 * may be deleted/cleaned up soon.
	 * @return true if the action is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool EndOfFile()
		{ return true; }

	/**
	 * Subclasses may override this to handle missing data in a file stream.
	 * @return true if the action is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool Undelivered(uint64 offset, uint64 len)
		{ return true; }

	/**
	 * @return the action type enum value.
	 */
	ActionTag Tag() const { return tag; }

	/**
	 * @return the ActionArgs associated with the aciton.
	 */
	RecordVal* Args() const { return args; }

	/**
	 * @return the file_analysis::File object to which the action is attached.
	 */
	File* GetFile() const { return file; }

	/**
	 * @return the action tag equivalent of the 'act' field from the ActionArgs
	 *         value \a args.
	 */
	static ActionTag ArgsTag(const RecordVal* args)
		{
		using BifType::Record::FileAnalysis::ActionArgs;
		return static_cast<ActionTag>(
		               args->Lookup(ActionArgs->FieldOffset("act"))->AsEnum());
		}

protected:

	Action(RecordVal* arg_args, File* arg_file)
	    : tag(Action::ArgsTag(arg_args)), args(arg_args->Ref()->AsRecordVal()),
	      file(arg_file)
		{}

	ActionTag tag;
	RecordVal* args;
	File* file;
};

typedef Action* (*ActionInstantiator)(RecordVal* args, File* file);

} // namespace file_analysis

#endif
