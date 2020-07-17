// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "Manager.h"
#include "Tag.h"
#include <iosource/Packet.h>

namespace zeek::packet_analysis {

/**
 * Result of packet analysis.
 */
enum class AnalyzerResult {
	Failed,   // Analysis failed
	Continue, // Analysis succeeded and an encapsulated protocol was determined
	Terminate // Analysis succeeded and there is no further analysis to do
};

using AnalysisResultTuple = std::tuple<AnalyzerResult, uint32_t>;

class Analyzer {
public:
	/**
	 * Constructor.
	 *
	 * @param name The name for the type of analyzer. The name must match
	 * the one the corresponding Component registers.
	 */
	explicit Analyzer(std::string name);

	/**
	 * Constructor.
	 *
	 * @param tag The tag for the type of analyzer. The tag must map to
	 * the name the corresponding Component registers.
	 */
	explicit Analyzer(const Tag& tag);

	/**
	 * Destructor.
	 */
	virtual ~Analyzer() = default;

	/**
	 * Returns the tag associated with the analyzer's type.
	 */
	const Tag GetAnalyzerTag() const;

	/**
	 * Returns a textual description of the analyzer's type. This is
	 * what's passed to the constructor and usually corresponds to the
	 * protocol name, e.g., "ARP".
	 */
	const char* GetAnalyzerName() const;

	/**
	 * Returns true if this analyzer's type matches the name passes in.
	 * This is shortcut for comparing GetAnalyzerName() with the given
	 * name.
	 *
	 * @param name The name to check.
	 */
	bool IsAnalyzer(const char* name);

	/**
	 * Analyzes the given packet. The data reference points to the part of the
	 * raw packet to be analyzed. If the analyzed protocol encapsulates another
	 * protocol, the data reference should be updated to point to that payload.
	 *
	 * @param packet The packet to analyze.
	 *
	 * @param data Reference to the payload pointer into the raw packet.
	 *
	 * @return A tuple of analysis result and identifier. The result indicates
	 * how to proceed. If analysis can continue, the identifier determines the
	 * encapsulated protocol.
	 */
	virtual AnalysisResultTuple Analyze(Packet* packet, const uint8_t*& data) = 0;

protected:
	friend class Manager;

private:
	Tag tag;

	void Init(const Tag& tag);
};

using AnalyzerPtr = std::shared_ptr<Analyzer>;

}
