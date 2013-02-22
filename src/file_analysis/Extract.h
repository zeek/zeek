#ifndef FILE_ANALYSIS_EXTRACT_H
#define FILE_ANALYSIS_EXTRACT_H

#include <string>

#include "Val.h"
#include "Info.h"
#include "Action.h"

namespace file_analysis {

/**
 * An action to simply extract files to disk.
 */
class Extract : public Action {
public:

	static Action* Instantiate(const RecordVal* args, Info* info);

	virtual ~Extract();

	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

protected:

	Extract(Info* arg_info, const string& arg_filename);

	string filename;
	int fd;
};

} // namespace file_analysis

#endif
