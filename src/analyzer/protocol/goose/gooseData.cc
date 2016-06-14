#include "gooseData.h"
#include "goose_pac.h"
//#include <memory>
#include <stack>
#include <vector>


// The index at which to Assign a VectorVal to a Record GOOSE::Data
#define GOOSE_DATA_ARRAY_INDEX 8 



namespace binpac { namespace GOOSE {

//==== Handling GOOSEData recusive structure ====

// Using a std::stack instead of a recursive call to avoid potential attacks
// on the host by stack overflow. This class bundles the information
// that is pushed on the container whenever a GOOSEData is an array of
// GOOSEData.
class GOOSEDataRecursionInfo {
public:
	RecordVal * scriptLandData;
	VectorVal * currentVectorVal;
	uint32 parsedBytes;
	uint32 totalSize;

	GOOSEDataRecursionInfo(uint8 tag, uint32 maxSize, RecordVal * newData)
		: scriptLandData(newData),
		  currentVectorVal(new VectorVal(BifType::Vector::GOOSE::SequenceOfData)),
		  parsedBytes(0),
		  totalSize(maxSize)
		{
		}
};

typedef std::stack<GOOSEDataRecursionInfo> GOOSEDataArrayRecursionStack;
typedef std::vector<GOOSE::GOOSEData*> VectorOfGOOSEData;

// When a GOOSEData is an array of GOOSEData
static inline void push_data_array(
		GOOSEDataArrayRecursionStack & vstack,
		const GOOSE::GOOSEData & data,
		RecordVal * newData)
{
	// Pushing info on the stack
	vstack.emplace(data.tag(), data.len()->value(), newData);
}

static inline void push_data_array(
		GOOSEDataArrayRecursionStack & vstack,
		const GOOSE::GOOSEData & data,
		uint8 tag)
{
	// Initializing the RecordVal holding the array
	auto tmpDat = new RecordVal(BifType::Record::GOOSE::Data);
	tmpDat->Assign(0, new Val(tag, TYPE_COUNT)); 

	push_data_array(vstack, data, tmpDat);
}


//===============================================

static inline void assignDataRecordContent(
		RecordVal * recordGooseData,
		uint8 tag,
		const GOOSEData & binpacGooseData)
{
	switch(tag) {
		case BOOLEAN:
			recordGooseData->Assign(1, new Val(binpacGooseData.content()->boolean(), TYPE_BOOL));
			break;
		case BCD:
			recordGooseData->Assign(2, new Val(binpacGooseData.content()->bcd()->val(), TYPE_INT));
			break;
		case SIGNED_INTEGER:
			recordGooseData->Assign(2, new Val(binpacGooseData.content()->intVal()->val(), TYPE_INT));
			break;
		case UNSIGNED_INTEGER:
			recordGooseData->Assign(3, new Val(binpacGooseData.content()->uintVal()->val(), TYPE_COUNT));
			break;
		case REAL:
			recordGooseData->Assign(4, new Val(binpacGooseData.content()->realVal()->value(), TYPE_DOUBLE));
			break;
		case FLOATING_POINT:
			if(binpacGooseData.content()->floatVal()->formatSupported())
				recordGooseData->Assign(4, new Val(binpacGooseData.content()->floatVal()->value(), TYPE_DOUBLE));
			break;
		case BIT_STRING:
			recordGooseData->Assign(5, asn1_bitstring_to_val(binpacGooseData.content()->bitString()));
			break;
		case BOOLEAN_ARRAY:
			recordGooseData->Assign(5, asn1_bitstring_to_val(binpacGooseData.content()->boolArray()));
			break;
		// All interpreted as a string
		case BINARY_TIME:
			// Documentation missing, interpreted as a string.
		case OCTET_STRING:
		case VISIBLE_STRING:
		case MMS_STRING:
			recordGooseData->Assign(6, bytestring_to_val(binpacGooseData.content()->asString()));
			break;
		case OBJ_ID:
			recordGooseData->Assign(6, asn1_oid_internal_to_val(binpacGooseData.content()->objId()));
			break;
		case UTCTIME:
			recordGooseData->Assign(7, gooseT_as_val(binpacGooseData.content()->utcTime())); 
			break;
	}
}

// This method is used by goose_data_array_as_record_val. It encapsulates the
// actions that happen at the end of its "while" loop.
// It commits all exported VectorVals in the case the parsed GOOSE Data array
// indicated a length that went beyond the packet frame. It also clears the
// stack of recusion info, saving the top Data record into a pointer.
static inline bool iteration_end_code(
	VectorOfGOOSEData::const_iterator & allDataIterator,
	const VectorOfGOOSEData::const_iterator & allDataEnd,
	GOOSEDataArrayRecursionStack & stackOfDataArrays,
	RecordVal * & loopDataPtr)
{
	++allDataIterator;
	if(allDataIterator == allDataEnd)
	{
		RecordVal * tmpDat;
		VectorVal * tmpVV;

		while(stackOfDataArrays.size() > 1)
		{
			// Committing the SequenceOfData into the Data :
			tmpDat = stackOfDataArrays.top().scriptLandData;
			tmpDat->Assign(GOOSE_DATA_ARRAY_INDEX, stackOfDataArrays.top().currentVectorVal);

			stackOfDataArrays.pop();

			// Append the Data to the VectorVal that was underneath
			tmpVV = stackOfDataArrays.top().currentVectorVal;
			tmpVV->Assign(tmpVV->Size(), tmpDat);
		}	

		// Committing the last SequenceOfData into the Data :
		tmpDat = stackOfDataArrays.top().scriptLandData;
		tmpDat->Assign(GOOSE_DATA_ARRAY_INDEX, stackOfDataArrays.top().currentVectorVal);

		stackOfDataArrays.pop();

		// Saving the record
		loopDataPtr = tmpDat;

		return false;
	}
	return true;
}

// This method is meant to export GOOSEData pac objects in the cases they are
// of type ARRAY or STRUCTURE.
static RecordVal * goose_data_array_as_record_val(
	VectorOfGOOSEData::const_iterator & allDataIterator,
	const VectorOfGOOSEData::const_iterator & allDataEnd,
	GOOSEDataArrayRecursionStack & stackOfDataArrays)
{
	VectorVal * tmpVV;
	RecordVal * tmpDat;
	uint8 tmpTag;

	auto dataPtr = *allDataIterator;

	tmpTag = dataPtr->tag();

	// Pushing the stack
	push_data_array(stackOfDataArrays, *dataPtr, tmpTag);
	tmpVV = stackOfDataArrays.top().currentVectorVal;

	while(iteration_end_code(allDataIterator, allDataEnd, stackOfDataArrays, tmpDat))
	{
		dataPtr = *allDataIterator;
		// Initialize the record that will hold the data taken from
		// *dataPtr
		tmpTag = dataPtr->tag();
		
		switch(tmpTag) {
			case STRUCTURE:
				// Same operations as the ARRAY case
			case ARRAY:
				// Add the length (in bytes) of the following array
				// to the size of the current one.
				stackOfDataArrays.top().parsedBytes += dataPtr->totalSize();
				push_data_array(stackOfDataArrays, *dataPtr, tmpTag);
				tmpVV = stackOfDataArrays.top().currentVectorVal;
				break;
			default:
				tmpDat = new RecordVal(BifType::Record::GOOSE::Data);
				tmpDat->Assign(0, new Val(tmpTag, TYPE_COUNT)); 
				assignDataRecordContent(tmpDat, tmpTag, *dataPtr);

				// Append the record to the vector
				tmpVV->Assign(tmpVV->Size(), tmpDat);

				// Add the length (in bytes) of the current GOOSEData to the count.
				stackOfDataArrays.top().parsedBytes += dataPtr->totalSize();
		}

		// A while loop is used to handle the cases where the last
		// Data of an array of Datas is an array of Data.
		while(stackOfDataArrays.top().parsedBytes
	           >= stackOfDataArrays.top().totalSize) // when it is >, it means the packet is malformed
		{
			//If the current GOOSEData is the last one of the current
			//array of GOOSEData :
			
			// Committing the SequenceOfData into the Data :
			tmpDat = stackOfDataArrays.top().scriptLandData;
			tmpDat->Assign(GOOSE_DATA_ARRAY_INDEX, tmpVV);

			stackOfDataArrays.pop();

			// If the current array of Data is a member of an an array of data :
			if(!stackOfDataArrays.empty())
			{
				// Append the Data to the VectorVal that was underneath
				tmpVV = stackOfDataArrays.top().currentVectorVal;
				tmpVV->Assign(tmpVV->Size(), tmpDat);
			}
			else
				return tmpDat; // Nothing else to do
		}
	}

	return tmpDat;
}


// This method is meant to export the field "allData" of the goosePdu.
VectorVal* goose_data_array_as_val(const VectorOfGOOSEData * dataArray)
{
	// The returned vector value.
	VectorVal * vv = new VectorVal(BifType::Vector::GOOSE::SequenceOfData);
	
	// The stack of information necessary to handle GOOSEData recursivity
	GOOSEDataArrayRecursionStack stackOfDataArrays;

	RecordVal * tmpDat;
	uint8 tmpTag;
	// Iteration over the parsed GOOSEData
	const auto end_iter = dataArray->cend();
	for(auto it=dataArray->cbegin(); it != end_iter ; ++it)
	{
		auto & dataPtr = *it; // reference to a pointer. Hopefully optimized away.

		tmpTag = dataPtr->tag();

		if(tmpTag != ARRAY && tmpTag != STRUCTURE) 
		{
			tmpDat = new RecordVal(BifType::Record::GOOSE::Data);
			tmpDat->Assign(0, new Val(tmpTag, TYPE_COUNT)); 
			assignDataRecordContent(tmpDat, tmpTag, *dataPtr);
		}
		else {
			tmpDat = goose_data_array_as_record_val(it, end_iter, stackOfDataArrays);

			// If the packet is malformed in a way that an array is said to be longer
			// than it actually is at the end of the packet, the iterator will here
			// be equal to end_iter.
			if(it == end_iter)
			{
				vv->Assign(vv->Size(), tmpDat);

				// Maybe notice the "Malformed packet" information somewhere.

				break; // To avoid the ++it, because here it==stackOfDataArrays.end()
			}
		}

		vv->Assign(vv->Size(), tmpDat);
	}

	return vv;
}

}} // End of namespaces

