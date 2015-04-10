// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_STRING_EXTRACT_H
#define FILE_ANALYSIS_STRING_EXTRACT_H

#include <vector>

#include "RE.h"
#include "Val.h"
#include "File.h"
#include "Analyzer.h"

//#include "analyzer/string_extract/events.bif.h"

namespace file_analysis {

/**
 * An analyzer to extract specific content of files to strings.
 */
class StringExtract : public file_analysis::Analyzer {
public:

	/**
	 * Destructor.
	 */
	~StringExtract();

	/**
	 * Check for string data to extract from a file.
	 * @param data pointer to a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 * @return true
	 */
	virtual bool DeliverStream(const u_char* data, uint64 len);

	/**
	 * Report undelivered bytes.
	 * @param offset distance into the file where the gap occurred.
	 * @param len number of bytes undelivered.
	 * @return true
	 */
	virtual bool Undelivered(uint64 offset, uint64 len);

	/**
	 * Create a new instance of an StringExtract analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new StringExtract analyzer instance or a null pointer if the
	 *         the insufficient arguments provided.
	 */
	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

	/**
	 * Sets the maximum allowed extracted file size.  A value of zero means
	 * "no limit".
	 * @param bytes number of bytes allowed to be extracted
	 */
	void SetLimit(uint64 bytes) { limit = bytes; }

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param arg_limit the maximum allowed file size.
	 * @param pre a preamble pattern to search for which comes before the
	 * content-to-extract.
	 * @param post a postable pattern to search for which comes after the
	 * content-to-extract.
	 * @param event event handler which will be called to receive extracted
	 * file data.
	 */
	StringExtract(RecordVal* args, File* file, uint64 arg_limit,
	              const char* pre, const char* post,
	              EventHandlerPtr event);

private:

	void Reset()
		{
		depth = 0;
		bytes_given_to_preamble_matcher = 0;
		bytes_given_to_postamble_matcher = 0;
		preamble->Clear();
		postamble->Clear();
		match_state = LOOKING_FOR_PREAMBLE;
		extracted_content = std::vector<u_char>();
		}

	void RaiseEvent(size_t len);

	enum MatchState {
		LOOKING_FOR_PREAMBLE,
		LOOKING_FOR_POSTAMBLE,
	};

	uint64 limit;
	uint64 depth;
	uint64 bytes_given_to_preamble_matcher;
	uint64 bytes_given_to_postamble_matcher;
	MatchState match_state;
	RE_Match_State_Range* preamble;
	RE_Match_State_Range* postamble;
	std::vector<u_char> extracted_content;
	EventHandlerPtr event;
};

} // namespace file_analysis

#endif
