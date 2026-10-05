##! The Broker-based Data API and its various options.

@load ./main
@load base/bif/data.bif

module Broker;

export {

	## Convert any Zeek value to communication data.
	##
	## .. note:: Normally you won't need to use this function as data
	##    conversion happens implicitly when passing Zeek values into Broker
	##    functions.
	##
	## d: any Zeek value to attempt to convert (not all types are supported).
	##
	## Returns: the converted communication data.  If the supplied Zeek data
	##          type does not support conversion to communication data, the
	##          returned record's optional field will not be set.
	global data: function(d: any): Broker::Data &deprecated="Remove in v10.1. This API is not useful after removal of Broker stores.";

	## Retrieve the type of data associated with communication data.
	##
	## d: the communication data.
	##
	## Returns: The data type associated with the communication data.
	##          Note that Broker represents records in the same way as
	##          vectors, so there is no "record" type.
	global data_type: function(d: Broker::Data): Broker::DataType &deprecated="Remove in v10.1. This API is not useful after removal of Broker stores.";
}

function data_type(d: Broker::Data): Broker::DataType
	{
	return __data_type(d);
	}

function data(d: any): Broker::Data
	{
	return __data(d);
	}
