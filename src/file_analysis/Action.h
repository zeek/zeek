#ifndef FILE_ANALYSIS_ACTION_H
#define FILE_ANALYSIS_ACTION_H

#include "Val.h"

namespace file_analysis {

class Info;

/**
 * Base class for actions that can be attached to a file_analysis::Info object.
 */
class Action {
public:

	virtual ~Action() {}

	/**
	 * Subclasses may override this to receive file data non-sequentially.
	 */
	virtual void DeliverChunk(const u_char* data, uint64 len, uint64 offset) {}

	/**
	 * Subclasses may override this to receive file sequentially.
	 */
	virtual void DeliverStream(const u_char* data, uint64 len) {}

	/**
	 * Subclasses may override this to specifically handle the end of a file.
	 */
	virtual void EndOfFile() {}

	/**
	 * Subclasses may override this to handle missing data in a file stream.
	 */
	virtual void Undelivered(uint64 offset, uint64 len) {}

protected:

	Action(Info* arg_info) {}

	Info* info;
};

typedef Action* (*ActionInstantiator)(const RecordVal* args, Info* info);

} // namespace file_analysis

#endif
