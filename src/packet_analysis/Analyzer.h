// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "Manager.h"
#include "Tag.h"
#include <iosource/Packet.h>

namespace zeek::packet_analysis {

/**
 * Result of packet analysis.
 */
 //TODO: Replace with bool?
enum class AnalyzerResult {
	Failed,   // Analysis failed
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
	 * Initialize the analyzer. This method is called after the configuration
	 * was read. Derived classes can override this method to implement custom
	 * initialization.
	 */
	virtual void Initialize() { };

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
	 * Registers an analyzer to be dispatched for the given identifier.
	 *
	 * @param identifier The identifier an analyzer should be called for.
	 * @param analyzer The analyzer that should be called.
	 * @return True if the registration was successful.
	 */
	bool RegisterAnalyzerMapping(uint32_t identifier, AnalyzerPtr analyzer);

	/**
	 * Registers a default analyzer.
	 *
	 * @param default_analyzer The analyzer to use as default.
	 */
	void RegisterDefaultAnalyzer(AnalyzerPtr default_analyzer);

	/**
	 * Analyzes the given packet. The data reference points to the part of the
	 * raw packet to be analyzed. If the analyzed protocol encapsulates another
	 * protocol, the data reference should be updated to point to that payload.
	 *
	 * @param packet The packet to analyze.
	 * @param data Reference to the payload pointer into the raw packet.
	 *
	 * @return A tuple of analysis result and identifier. The result indicates
	 * how to proceed. If analysis can continue, the identifier determines the
	 * encapsulated protocol.
	 */
	virtual AnalyzerResult Analyze(Packet* packet, const uint8_t*& data) = 0;

protected:
	friend class Manager;

	/**
	 * Looks up the analyzer for the encapsulated protocol based on the given
	 * identifier.
	 *
	 * @param identifier Identifier for the encapsulated protocol.
	 * @return The analyzer registered for the given identifier. Returns a
	 * nullptr if no analyzer is registered.
	 */
	AnalyzerPtr Lookup(uint32_t identifier) const;

	/**
	 * Triggers analysis of the encapsulated packet. The encapsulated protocol
	 * is determined using the given identifier.
	 *
	 * @param packet The packet to analyze.
	 * @param data Reference to the payload pointer into the raw packet.
	 * @param identifier The identifier of the encapsulated protocol.
	 *
	 * @return The outcome of the analysis.
	 */
	virtual AnalyzerResult AnalyzeInnerPacket(Packet* packet, const uint8_t*& data,
	                                          uint32_t identifier) const;

	/**
	 * Triggers default analysis of the encapsulated packet if the default analyzer
	 * is set.
	 *
	 * @param packet The packet to analyze.
	 * @param data Reference to the payload pointer into the raw packet.
	 *
	 * @return The outcome of the analysis.
	 */
	AnalyzerResult AnalyzeInnerPacket(Packet* packet, const uint8_t*& data) const;

private:
	Tag tag;
	Dispatcher dispatcher;
	AnalyzerPtr default_analyzer = nullptr;

	void Init(const Tag& tag);
};

using AnalyzerPtr = std::shared_ptr<Analyzer>;

}
