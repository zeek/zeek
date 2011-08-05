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
		RESPONSE -> objects: Response_Objects[];
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
	prefix: case(object_header.qualifier_field & 0xf0 ) of {
                0x00 -> none: empty &check(object_header.qualifier_field == 0x01 ||
                                                object_header.qualifier_field == 0x02 ||
                                                object_header.qualifier_field == 0x03 ||
                                                object_header.qualifier_field == 0x04 ||
                                                object_header.qualifier_field == 0x05 ||
                                                object_header.qualifier_field == 0x06 ||
                                                object_header.qualifier_field == 0x07 ||
                                                object_header.qualifier_field == 0x08 ||
                                                object_header.qualifier_field == 0x09 );
                0x10 -> prefix8: uint8 &check(object_header.qualifier_field == 0x17 ||
                                                object_header.qualifier_field == 0x18 ||
                                                object_header.qualifier_field == 0x19 );
                0x20 -> prefix16: uint16 &check(object_header.qualifier_field == 0x27 ||
                                                object_header.qualifier_field == 0x28 ||
                                                object_header.qualifier_field == 0x29 );
                0x30 -> prefix32: uint32 &check(object_header.qualifier_field == 0x37 ||
                                                object_header.qualifier_field == 0x38 ||
                                                object_header.qualifier_field == 0x39 );
                0x40 -> object_size8: uint8 &check(object_header.qualifier_field == 0x4B);
                0x50 -> object_size16: uint16 &check(object_header.qualifier_field == 0x5B);
                0x60 -> object_size32: uint32 &check(object_header.qualifier_field == 0x6B);
	 	default -> unknownprefix: empty;
        };
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
	prefix: case(object_header.qualifier_field & 0xf0 ) of {
		0x00 -> none: empty &check(object_header.qualifier_field == 0x01 ||
						object_header.qualifier_field == 0x02 ||
						object_header.qualifier_field == 0x03 ||
						object_header.qualifier_field == 0x04 ||
						object_header.qualifier_field == 0x05 ||	
						object_header.qualifier_field == 0x06 ||
						object_header.qualifier_field == 0x07 ||
						object_header.qualifier_field == 0x08 ||
						object_header.qualifier_field == 0x09 );
		0x10 -> prefix8: uint8 &check(object_header.qualifier_field == 0x17 || 
						object_header.qualifier_field == 0x18 ||
						object_header.qualifier_field == 0x19 );
		0x20 -> prefix16: uint16 &check(object_header.qualifier_field == 0x27 ||
                                                object_header.qualifier_field == 0x28 ||
                                                object_header.qualifier_field == 0x29 );
		0x30 -> prefix32: uint32 &check(object_header.qualifier_field == 0x37 ||
                                                object_header.qualifier_field == 0x38 ||
                                                object_header.qualifier_field == 0x39 );
		0x40 -> object_size8: uint8 &check(object_header.qualifier_field == 0x4B);
		0x50 -> object_size16: uint16 &check(object_header.qualifier_field == 0x5B);
		0x60 -> object_size32: uint32 &check(object_header.qualifier_field == 0x6B);
		default -> unknownprefix: empty;
	};
	data: case(object_header.object_type_field) of {
		0x0101 -> biwoflag: uint8[ ( object_header.number_of_item / 8 ) ];  # warning: returning integer index?
		0x0102 -> biwflag: uint8;  # warning: only flag?
		
		0x0a01 -> bowoflag:  uint8[ ( object_header.number_of_item / 8 ) ];  # warning: returning integer index?	
		0x0a02 -> bowflag: uint8;  # warning: only flag?
		
		0x1e01 -> ai_32_wflag: AnalogInput32wFlag[object_header.number_of_item];
                0x1e02 -> ai_16_wflag: AnalogInput16wFlag[object_header.number_of_item];
                0x1e03 -> ai_32_woflag: AnalogInput32woFlag[object_header.number_of_item];
                0x1e04 -> ai_16_woflag: AnalogInput16woFlag[object_header.number_of_item];
                0x1e05 -> ai_sp_wflag: AnalogInputSPwFlag[object_header.number_of_item];
                0x1e06 -> ai_dp_wflag: AnalogInputDPwFlag[object_header.number_of_item];
		
		0x2001 -> ai32wotime: AnalogInput32woTime[object_header.number_of_item];
		0x2002 -> ai16wotime: AnalogInput16woTime[object_header.number_of_item];
		0x2003 -> ai32wtime:  AnalogInput32wTime[object_header.number_of_item];
		0x2004 -> ai16wtime:  AnalogInput16wTime[object_header.number_of_item];
		0x2005 -> aispwotime: AnalogInputSPwoTime[object_header.number_of_item];
		0x2006 -> aidpwotime: AnalogInputDPwoTime[object_header.number_of_item];
		0x2007 -> aispwtime:  AnalogInputSPwTime[object_header.number_of_item];
		0x2008 -> aidpwtime:  AnalogInputDPwTime[object_header.number_of_item];
	};
};


type Object_Header = record {
	object_type_field : uint16; #Object_Type;
	qualifier_field: uint8;
	range_field: case ( qualifier_field & 0x0f ) of {  # warning
		0 -> range_field_0: Range_Field_0 &check(range_field_0.stop_index >= range_field_0.start_index);
		1 -> range_field_1: Range_Field_1 &check(range_field_1.stop_index >= range_field_1.start_index);
		2 -> range_field_2: Range_Field_2 &check(range_field_2.stop_index >= range_field_2.start_index);
		3 -> range_field_3: Range_Field_3;
		4 -> range_field_4: Range_Field_4;
		5 -> range_field_5: Range_Field_5;
		6 -> range_field_6: empty;
		7 -> range_field_7: uint8;
		8 -> range_field_8: uint16;
		9 -> range_field_9: uint32;
		0x0b -> range_field_b: uint8;
		default -> unknown: bytestring &restofdata;	
	};
} &let{
	number_of_item: uint32 = case (qualifier_field & 0x0f) of {
		1 -> (range_field_0.stop_index - range_field_0.start_index + 1);
		2 -> (range_field_1.stop_index - range_field_1.start_index + 1);
		3 -> (range_field_2.stop_index - range_field_2.start_index + 1);
		7 -> range_field_7;  # data type warning?
		8 -> range_field_8;
		9 -> range_field_9;
		0x0b -> range_field_b;
		default -> 0;
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

# group: 30; variation: 1
type AnalogInput32wFlag = record{
        flag: uint8;
        value: uint32;
};
# group: 30; variation: 2
type AnalogInput16wFlag = record{
        flag: uint8;
        value: uint16;
};
# group: 30; variation: 3
type AnalogInput32woFlag = record{
        value: uint32;
};
# group: 30; variation: 4
type AnalogInput16woFlag = record{
        value: uint16;
};
# group: 30; variation: 5; singple precision 32 bit
type AnalogInputSPwFlag = record{
        flag: uint8;
        value: uint32;
};
# group: 30; variation: 6; double precision 64 bit
type AnalogInputDPwFlag = record{
        flag: uint8;
        value: uint32[2];
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
