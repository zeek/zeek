# $Id:$
#
# This template code contributed by Kristin Stephens.

type Dnp3_PDU(is_orig: bool) = case is_orig of {
	true    ->  request:  Dnp3_Request;
	false   ->  response: Dnp3_Response;
} &byteorder = bigendian;

type Dnp3_Request = record {
	app_header: Dnp3_Application_Request_Header;
	data: case app_header.function_code of {
		CONFIRM -> none_coonfirm: empty;
		READ -> objects: Request_Objects[];
		default -> unknown: bytestring &restofdata;
	};
};

type Dnp3_Response = record {
	app_header: Dnp3_Application_Response_Header;
	data: case app_header.function_code of {
		#READ -> 
		default -> unknown: bytestring &restofdata;
	};
};



type Dnp3_Application_Request_Header = record {
	application_control : uint8;
	function_code       : uint8;
} ;

type Dnp3_Application_Response_Header = record {
	application_control  : uint8;
	function_code        : uint8;
	internal_indications : Response_Internal_Indication;
};

type Response_Internal_Indication = record {
	first_octet: uint8;
	second_octet: uint8;
};

type Request_Objects = record {
	object_header: Object_Header;
	data: case (object_header.object_type_field) of {
		0x2001 -> ai32wotime: empty;
		0x2002 -> ai16wotime: empty;
		0x2003 -> ai32wtime:  empty;
                0x2004 -> ai16wtime:  empty;
                0x2005 -> aispwotime: empty;
                0x2006 -> aidpwotime: empty;
                0x2007 -> aispwtime:  empty;
                0x2008 -> aidpwtime:  empty;
		0x3C01 -> class0data: empty &check(object_header.qualifier_field == 0x06);
		0x3C02 -> class1data: empty &check(object_header.qualifier_field == 0x06 || 
							object_header.qualifier_field == 0x07 || object_header.qualifier_field == 0x08);
		0x3C03 -> class2data: empty &check(object_header.qualifier_field == 0x06 || 
							object_header.qualifier_field == 0x07 || object_header.qualifier_field == 0x08);
		0x3C04 -> class3data: empty &check(object_header.qualifier_field == 0x06 || 
							object_header.qualifier_field == 0x07 || object_header.qualifier_field == 0x08);
		default -> unknown: bytestring &restofdata;
	};	
};

type Response_Objects = record {
	object_header: Object_Header;
	data: case(object_header.object_type_field) of {
		0x2001 -> ai32wotime: AnalogInput32woTime;
		0x2002 -> ai16wotime: AnalogInput16woTime;
		0x2003 -> ai32wtime:  AnalogInput32wTime;
		0x2004 -> ai16wtime:  AnalogInput16wTime;
		0x2005 -> aispwotime: AnalogInputSPwoTime;
		0x2006 -> aidpwotime: AnalogInputDPwoTime;
		0x2007 -> aispwtime:  AnalogInputSPwTime;
		0x2008 -> aidpwtime:  AnalogInputDPwTime;
	};
};


type Object_Header = record {
	object_type_field : uint16; #Object_Type;
	qualifier_field: uint8;
	range_field: case ( qualifier_field & 0x0f ) of {  # warning
		0 -> range_field_0: Range_Field_0;
		1 -> range_field_1: Range_Field_1;
		2 -> range_field_2: Range_Field_2;
		3 -> range_field_3: Range_Field_3;
		4 -> range_field_4: Range_Field_4;
		5 -> range_field_5: Range_Field_5;
		6 -> range_field_6: empty;
		7 -> range_field_7: Range_Field_7;
		8 -> range_field_8: Range_Field_8;
		9 -> range_field_9: Range_Field_9;
		0xb -> range_field_b: Range_Field_B;
		default -> unknown: bytestring &restofdata;	
	};
};

#type Object_Type = record {
#	object_group: uint8;
#	object_variation: uint8;
#};

type Range_Field_0 = record {
	start_index: uint8;
	stop_index: uint8;
};

type Range_Field_1 = record {
        start_index: uint16;
	stop_index: uint16;
};

type Range_Field_2 = record {
        start_index: uint32;
        stop_index: uint32;
};

type Range_Field_3 = record {
        start_addr: uint8;
        stop_addr: uint8;
};

type Range_Field_4 = record {
        start_addr: uint16;
        stop_addr: uint16;
};

type Range_Field_5 = record {
        start_addr: uint32;
        stop_addr: uint32;
};

type Range_Field_7 = record {
        object_count: uint8;
};

type Range_Field_8 = record {
        object_count: uint16;
};

type Range_Field_9 = record {
        object_count: uint32;
};

type Range_Field_B = record {
        object_count: uint8;
};

type Object_With_Header = record {
	object_header: Object_Header;

};

# group: 32; variation: 1
type AnalogInput32woTime = record{
	flag: uint8;
	value: uint32;
};
# group: 32; variation: 2
type AnalogInput16woTime = record{
	flag: uint8;
	value: uint16;
};
# group: 32; variation: 3
type AnalogInput32wTime = record{
	flag: uint8;
	value: uint32;
	time: uint8[6];
};
# group: 32; variation: 4
type AnalogInput16wTime = record{
	flag: uint8;
	value: uint16;
	time: uint8[6];
};
# group: 32; variation: 5; singple precision 32 bit
type AnalogInputSPwoTime = record{
	flag: uint8;
	value: uint32;
};
# group: 32; variation: 6; double precision 64 bit
type AnalogInputDPwoTime = record{
	flag: uint8;
	value: uint32[2];
};
# group: 32; variation: 7
type AnalogInputSPwTime = record{
	flag: uint8;
	value: uint32;
	time: uint8[6];
};
# group: 32; variation: 8
type AnalogInputDPwTime = record{
	flag: uint8;
	value: uint32[2];
	time: uint8[6];
};
enum function_codes_value {
	CONFIRM = 0x00,
	READ = 0x01,
	WRITE = 0x02,
	SELECT = 0x03,
	OPERATE = 0x04,
	DIRECT_OPERATE = 0x05,
	DIRECT_OPERATE_NR = 0x06,
	IMMED_FREEZE = 0x07,
	IMMED_FREEZE_NR = 0x08,
	FREEZE_CLEAR = 0x09,
	FREEZE_CLEAR_NR = 0x0a,
	FREEZE_AT_TIME = 0x0b,
	FREEZE_AT_TIME_NR = 0x0c,
	COLD_RESTART = 0x0d,
	WARM_RESTART = 0x0e,
	INITIALIZE_DATA = 0x0f,
	INITIALIZE_APPL = 0x10,
	START_APPL = 0x11,
	STOP_APPL = 0x12,
	SAVE_CONFIG = 0x13,
	ENABLE_UNSOLICITED = 0x14,
	DISABLE_UNSOLICITED = 0x15,
	ASSIGN_CLASS = 0x16,
	DELAY_MEASURE = 0x17,
	RECORD_CURRENT_TIME = 0x18,
	OPEN_FILE = 0x19,
	CLOSE_FILE = 0x1a,
	DELETE_FILE = 0x1b,
	GET_FILE_INFO = 0x1c,
	AUTHENTICATE_FILE = 0x1d,
	ABORT_FILE = 0x1e,
	ACTIVATE_CONFIG = 0x1f,
	AUTHENTICATE_REQ = 0x20,
	AUTHENTICATE_ERR = 0x21,
# researved
	RESPONSE = 0x81,
	UNSOLICITED_RESPONSE = 0x82,
	AUTHENTICATE_RESP = 0x83,
# researved	
};
