
module GOOSE;

export {
	## The different types of data that a GOOSE::Data can hold, as
	## described in the IEC 61850. It will be referred as the
	## "official type".
	const GOOSE_DATA_TYPE_ARRAY: count = 0x81;
	const GOOSE_DATA_TYPE_STRUCTURE: count = 0x82;
	const GOOSE_DATA_TYPE_BOOLEAN: count = 0x83;
	const GOOSE_DATA_TYPE_BIT_STRING: count = 0x84;
	const GOOSE_DATA_TYPE_INTEGER: count = 0x85;
	const GOOSE_DATA_TYPE_UNSIGNED: count = 0x86;
	const GOOSE_DATA_TYPE_FLOATING_POINT: count = 0x87;
	const GOOSE_DATA_TYPE_REAL: count = 0x88;
	const GOOSE_DATA_TYPE_OCTET_STRING: count = 0x89;
	const GOOSE_DATA_TYPE_VISIBLE_STRING: count = 0x8a;
	const GOOSE_DATA_TYPE_BINARY_TIME: count = 0x8c;
	const GOOSE_DATA_TYPE_BCD: count = 0x8d;
	const GOOSE_DATA_TYPE_BOOLEAN_ARRAY: count = 0x8e;
	const GOOSE_DATA_TYPE_OBJ_ID: count = 0x8f;
	const GOOSE_DATA_TYPE_MMS_STRING: count = 0x90;
	const GOOSE_DATA_TYPE_UTC_TIME: count = 0x91;
}
