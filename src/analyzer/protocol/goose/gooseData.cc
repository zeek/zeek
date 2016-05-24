#include "gooseData.h"
#include <memory>

//==== Handling GOOSEData recusive structure ====

// Using a std::stack instead of a recursive call to avoid potential attacks
// on the host by stack overflow. This class bundles the information
// that is pushed on the container whenever a GOOSEData is an array of
// GOOSEData.
class GOOSEDataRecursionInfo {
public:
	VectorVal * currentVectorVal;
	uint32 currentDataArrayParsedBytes;
	uint32 currentDataArrayTotalSize;

	GOOSEDataRecursionInfo(VectorVal * vv, uint32 maxSize)
		: currentVectorVal(vv),
		  currentDataArrayParsedBytes(0),
		  currentDataArrayTotalSize(maxSize)
		{}
};

typedef std::stack<GOOSEDataRecursionInfo> GOOSEDataArrayRecursionStack;

// When a GOOSEData is an array of GOOSEData
static inline void handle_data_array(GOOSEDataArrayRecursionStack & vstack, const GOOSE::GOOSEData & data)
	// Pushing info on the stack
	vstack.emplace(new VectorVal(BifType::Vector::GOOSE::SequenceOfData, data.len().value());
}

//===============================================

VectorVal* goose_data_array_as_val(const std::vector<GOOSE::GOOSEData> & dataArray)
{
	// The returned vector value.
	VectorVal * vv = new VectorVal(BifType::Record::GOOSE::Data);
	
	// The stack of information necessary to handle GOOSEData recursivity
	GOOSEDataArrayRecursionStack stackOfDataArrays;

	// Iteration over the parsed GOOSEData
	const auto end_iter = dataArray.cend();
	for(auto it=dataArray.cbegin(); it =! end_iter ; ++it)
	{
		// if we are not parsing a GOOSEData at depth 0
		if(!stackOfDataArrays.empty())
		{
			//Check size
			// Commit the VectorVal to the contingent one underneath it
		}
		switch(it->tag()) {
			case ARRAY:
				
		}
	}

	return vv;
}
