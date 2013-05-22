// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_ANALYZER_H
#define FILE_ANALYSIS_ANALYZER_H

#include "Val.h"
#include "NetVar.h"

namespace file_analysis {

typedef BifEnum::FileAnalysis::Analyzer FA_Tag;

class File;

/**
 * Base class for analyzers that can be attached to file_analysis::File objects.
 */
class Analyzer {
public:
	virtual ~Analyzer()
		{
		DBG_LOG(DBG_FILE_ANALYSIS, "Destroy file analyzer %d", tag);
		Unref(args);
		}

	/**
	 * Subclasses may override this to receive file data non-sequentially.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset)
		{ return true; }

	/**
	 * Subclasses may override this to receive file sequentially.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool DeliverStream(const u_char* data, uint64 len)
		{ return true; }

	/**
	 * Subclasses may override this to specifically handle an EOF signal,
	 * which means no more data is going to be incoming and the analyzer
	 * may be deleted/cleaned up soon.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool EndOfFile()
		{ return true; }

	/**
	 * Subclasses may override this to handle missing data in a file stream.
	 * @return true if the analyzer is still in a valid state to continue
	 *         receiving data/events or false if it's essentially "done".
	 */
	virtual bool Undelivered(uint64 offset, uint64 len)
		{ return true; }

	/**
	 * @return the analyzer type enum value.
	 */
	FA_Tag Tag() const { return tag; }

	/**
	 * @return the AnalyzerArgs associated with the analyzer.
	 */
	RecordVal* Args() const { return args; }

	/**
	 * @return the file_analysis::File object to which the analyzer is attached.
	 */
	File* GetFile() const { return file; }

	/**
	 * @return the analyzer tag equivalent of the 'tag' field from the
	 *         AnalyzerArgs value \a args.
	 */
	static FA_Tag ArgsTag(const RecordVal* args)
		{
		using BifType::Record::FileAnalysis::AnalyzerArgs;
		return static_cast<FA_Tag>(
		              args->Lookup(AnalyzerArgs->FieldOffset("tag"))->AsEnum());
		}

protected:
	Analyzer(RecordVal* arg_args, File* arg_file)
	    : tag(file_analysis::Analyzer::ArgsTag(arg_args)),
	      args(arg_args->Ref()->AsRecordVal()),
	      file(arg_file)
		{}

private:
	FA_Tag tag;
	RecordVal* args;
	File* file;
};

typedef file_analysis::Analyzer* (*AnalyzerInstantiator)(RecordVal* args,
                                                         File* file);

} // namespace file_analysis

#endif
