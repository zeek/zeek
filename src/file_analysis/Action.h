#ifndef FILE_ANALYSIS_ACTION_H
#define FILE_ANALYSIS_ACTION_H

#include "Val.h"
#include "NetVar.h"

namespace file_analysis {

typedef BifEnum::FileAnalysis::Action ActionTag;

class Info;

/**
 * Base class for actions that can be attached to a file_analysis::Info object.
 */
class Action {
public:

	virtual ~Action() {}

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
	 * Subclasses may override this to specifically handle the end of a file.
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

	ActionTag Tag() const { return tag; }

protected:

	Action(Info* arg_info, ActionTag arg_tag) : info(arg_info), tag(arg_tag) {}

	Info* info;
	ActionTag tag;
};

typedef Action* (*ActionInstantiator)(const RecordVal* args, Info* info);

} // namespace file_analysis

#endif
