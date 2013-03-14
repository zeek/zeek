#ifndef FILE_ANALYSIS_PE_H
#define FILE_ANALYSIS_PE_H

#include <string>

#include "Val.h"
#include "../Info.h"
#include "pe_pac.h"

namespace file_analysis {

/**
 * An action to simply extract files to disk.
 */
class PE_Analyzer : Action {
public:
	static Action* Instantiate(const RecordVal* args, Info* info);

	~PE_Analyzer();

	virtual bool DeliverStream(const u_char* data, uint64 len);

protected:

	PE_Analyzer(Info* arg_info);
	binpac::PE::File* interp;
};

} // namespace file_analysis

#endif
