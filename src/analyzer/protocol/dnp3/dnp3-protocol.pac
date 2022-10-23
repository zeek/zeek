#
# This is Binpac code for DNP3 analyzer by Hui Lin.
#

type DNP3_PDU(is_orig: bool) = case is_orig of {
	true    ->  request:  DNP3_Request;
	false   ->  response: DNP3_Response;
} &byteorder = bigendian;

type Header_Block = record {
	start_1: uint8 &enforce(start_1 == 0x05);
	start_2: uint8 &enforce(start_2 == 0x64);
	len: uint8;
	ctrl: uint8;
	dest_addr: uint16;
	src_addr: uint16;
} &byteorder = littleendian;

type DNP3_Request = record {
	addin_header: Header_Block;  ## added by Hui Lin in Zeek code
	app_header: DNP3_Application_Request_Header;
	data: case ( app_header.function_code ) of {
		CONFIRM -> none_confirm: empty;
		READ -> read_requests: Request_Objects(app_header.function_code)[];
		WRITE -> write_requests: Request_Objects(app_header.function_code)[];
		SELECT -> select_requests: Request_Objects(app_header.function_code)[];
		OPERATE -> operate_requests: Request_Objects(app_header.function_code)[];
		DIRECT_OPERATE -> direct_operate_requests: Request_Objects(app_header.function_code)[];
		DIRECT_OPERATE_NR -> direct_operate_nr_requests: Request_Objects(app_header.function_code)[];
		IMMED_FREEZE -> immed_freeze_requests: Request_Objects(app_header.function_code)[];
		IMMED_FREEZE_NR -> immed_freeze_nr_requests: Request_Objects(app_header.function_code)[];
		FREEZE_CLEAR -> freeze_clear_requests: Request_Objects(app_header.function_code)[];
		FREEZE_CLEAR_NR -> freeze_clear_nr_requests: Request_Objects(app_header.function_code)[];
		FREEZE_AT_TIME -> freeze_time_requests: Request_Objects(app_header.function_code)[];
		FREEZE_AT_TIME_NR -> freeze_time_nr_requests: Request_Objects(app_header.function_code)[];
		COLD_RESTART -> cold_restart: empty;
		WARM_RESTART -> warm_restart: empty;
		INITIALIZE_DATA -> initilize_data: empty;  # obsolete
		INITIALIZE_APPL -> initilize_appl: Request_Objects(app_header.function_code)[];
		START_APPL -> start_appl: Request_Objects(app_header.function_code)[];
		STOP_APPL -> stop_appl: Request_Objects(app_header.function_code)[];
		SAVE_CONFIG -> save_config: empty;  # depracated
		ENABLE_UNSOLICITED -> enable_unsolicited: Request_Objects(app_header.function_code)[];
		DISABLE_UNSOLICITED -> disable_unsolicited: Request_Objects(app_header.function_code)[];
		ASSIGN_CLASS -> assign_class: Request_Objects(app_header.function_code)[];
		DELAY_MEASURE -> delay_measure: empty;
		RECORD_CURRENT_TIME -> record_cur_time: empty;
		OPEN_FILE -> open_file: Request_Objects(app_header.function_code)[];
		CLOSE_FILE -> close_file: Request_Objects(app_header.function_code)[];
		DELETE_FILE -> delete_file: Request_Objects(app_header.function_code)[];
		ABORT_FILE -> abort_file: Request_Objects(app_header.function_code)[];
		GET_FILE_INFO -> get_file_info: Request_Objects(app_header.function_code)[];
		AUTHENTICATE_FILE  -> auth_file: Request_Objects(app_header.function_code)[];
		ACTIVATE_CONFIG  -> active_config: Request_Objects(app_header.function_code)[];
		AUTHENTICATE_REQ  -> auth_req: Request_Objects(app_header.function_code)[];
		AUTHENTICATE_ERR  -> auth_err: Request_Objects(app_header.function_code)[];
		default -> unknown: bytestring &restofdata;
	};
} &byteorder = bigendian
  &length= 9 + addin_header.len - 5 - 1;

type Debug_Byte = record {
	debug: bytestring &restofdata;
};

type DNP3_Response = record {
	addin_header: Header_Block;
	app_header: DNP3_Application_Response_Header;
	data: case ( app_header.function_code ) of {
		RESPONSE -> response_objects: Response_Objects(app_header.function_code)[];
		UNSOLICITED_RESPONSE -> unsolicited_response_objects: Response_Objects(app_header.function_code)[];
		AUTHENTICATE_RESP -> auth_response: Response_Objects(app_header.function_code)[];
		default -> unknown: Debug_Byte;
	};
} &byteorder = bigendian
  &length= 9 + addin_header.len - 5 - 1;

type DNP3_Application_Request_Header = record {
	empty: bytestring &length = 0; # Work-around BinPAC problem.
	application_control : uint8;
	function_code       : uint8 ;
} &length = 2;

type DNP3_Application_Response_Header = record {
	empty: bytestring &length = 0; # Work-around BinPAC problem.
	application_control  : uint8;
	function_code	: uint8;
	internal_indications : uint16;
} &length = 4;

type Request_Objects(function_code: uint8) = record {
	object_header: Object_Header(function_code);
	data: case (object_header.object_type_field) of {
		# binary output command g12
		0x0c01 -> g12v1_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x0c02 -> g12v2_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x0c03 -> bocmd_PM: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ ( object_header.number_of_item / 8 ) + 1*( object_header.number_of_item > ( (object_header.number_of_item / 8)*8 ) ) ];

		# time data interval data object g50
		0x3201 -> g50v1_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		#0x3202 -> time_interval_ojbects: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
						# &check( object_header.qualifier_field == 0x0f && object_header.number_of_item == 0x01);
		0x3202 -> g50v2_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x3203 -> g50v3_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];

		# Time and Date Common Time-of-Occurrence g51
		0x3301 -> g51v1_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x3302 -> g51v2_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];

		# time delay g52
		0x3401 -> g52v1_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x3402 -> g52v2_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];

		# file control g70
		0x4601 -> g70v1_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x4602 -> g70v2_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x4603 -> g70v3_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x4604 -> g70v4_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x4605 -> g70v5_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x4606 -> g70v6_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x4607 -> g70v7_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];

		# internal indication g80
		0x5001 -> g80v1_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];

		# authentication challenge g120
		0x7801 -> g120v1_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7802 -> g120v2_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7803 -> g120v3_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7804 -> g120v4_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7805 -> g120v5_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7806 -> g120v6_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7807 -> g120v7_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7808 -> g120v8_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x7809 -> g120v9_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x780A -> g120v10_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x780B -> g120v11_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x780C -> g120v12_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x780D -> g120v13_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x780E -> g120v14_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		0x780F -> g120v15_objs: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];

		# default -> ojbects: Request_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
		default -> objects: empty;
	};
	# dump_data is always empty; I intend to use it for checking some conditions;
	# However, in the current binpac implementation, &check is not implemented
	dump_data: case (function_code) of {
		OPEN_FILE -> open_file_dump: empty; # &check(object_header.object_type_field == 0x4603);
		CLOSE_FILE -> close_file_dump: empty; # &check(object_header.object_type_field == 0x4604);
		DELETE_FILE -> delete_file_dump: empty; # &check(object_header.object_type_field == 0x4603);
		ABORT_FILE -> abort_file_dump: empty; # &check(object_header.object_type_field == 0x4604);
		GET_FILE_INFO -> get_file_info: empty; # &check(object_header.object_type_field == 0x4607);
		AUTHENTICATE_FILE  -> auth_file: empty; # &check(object_header.object_type_field == 0x4602);
		ACTIVATE_CONFIG  -> active_config: empty; # &check(object_header.object_type_field == 0x4608 || (object_header.object_type_field & 0xFF00) == 0x6E00);
		default -> default_dump: empty;
	};
};

type Response_Objects(function_code: uint8) = record {
	object_header: Object_Header(function_code);
	data: case (object_header.object_type_field) of {
		0x0101 -> biwoflag: Response_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ ( object_header.number_of_item / 8 ) + 1*( object_header.number_of_item > ( (object_header.number_of_item / 8)*8 ) ) ];
		0x0301 -> diwoflag: Response_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ ( object_header.number_of_item / 8 ) + 1*( object_header.number_of_item > ( (object_header.number_of_item / 8)*8 ) ) ];
		0x0a01 -> bowoflag: Response_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ ( object_header.number_of_item / 8 ) + 1*( object_header.number_of_item > ( (object_header.number_of_item / 8)*8 ) )];
		0x0c03 -> bocmd_PM: Response_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ ( object_header.number_of_item / 8 ) + 1*( object_header.number_of_item > ( (object_header.number_of_item / 8)*8 ) )];
		default -> objects: Response_Data_Object(function_code, object_header.qualifier_field, object_header.object_type_field )[ object_header.number_of_item];
	};
};

type Object_Header(function_code: uint8) = record {
	object_type_field: uint16 ;
	qualifier_field: uint8 ;
	range_field: case ( qualifier_field & 0x0f ) of {
		0 -> range_field_0: Range_Field_0; # &check(range_field_0.stop_index >= range_field_0.start_index);
		1 -> range_field_1: Range_Field_1; # &check(range_field_1.stop_index >= range_field_1.start_index);
		2 -> range_field_2: Range_Field_2; # &check(range_field_2.stop_index >= range_field_2.start_index);
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
	# dump_data is always empty; used to check dependency bw object_type_field and qualifier_field
	dump_data: case ( object_type_field & 0xff00 ) of {
		0x3C00 -> dump_3c: empty; # &check( (object_type_field == 0x3C01 || object_type_field == 0x3C02 || object_type_field == 0x3C03 || object_type_field == 0x3C04) && ( qualifier_field == 0x06 ) );
		default -> dump_def: empty;
	};
}
      &let{
	number_of_item: int = case (qualifier_field & 0x0f) of {
		0 -> (range_field_0.stop_index - range_field_0.start_index + 1);
		1 -> (range_field_1.stop_index - range_field_1.start_index + 1);
		2 -> (range_field_2.stop_index - range_field_2.start_index + 1);
		7 -> range_field_7;
		8 -> ( range_field_8 & 0x0ff )* 0x100 + ( range_field_8 / 0x100 ) ;
		9 -> ( range_field_9 & 0x000000ff )* 0x1000000 + (range_field_9 & 0x0000ff00) * 0x100 + (range_field_9 & 0x00ff0000) / 0x100 + (range_field_9 & 0xff000000) / 0x1000000 ;
		0x0b -> range_field_b;
		default -> 0;
	};
	rf_value_low: int = case (qualifier_field & 0x0f) of {
		0 -> 0 + range_field_0.start_index;
		1 -> range_field_1.start_index;
		2 -> range_field_2.start_index;
		3 -> range_field_3.start_addr;
		4 -> range_field_4.start_addr;
		5 -> range_field_5.start_addr;
		6 -> 0xffff;
		7 -> range_field_7;
		8 -> range_field_8;
		9 -> range_field_9;
		0x0b -> range_field_b;
		default -> 0 ;
	};
	rf_value_high: int = case (qualifier_field & 0x0f) of {
		0 -> 0 + range_field_0.stop_index;
		1 -> range_field_1.stop_index;
		2 -> range_field_2.stop_index;
		3 -> range_field_3.stop_addr;
		4 -> range_field_4.stop_addr;
		5 -> range_field_5.stop_addr;
		6 -> 0xffff;
		default -> 0 ;
	};
};

type Range_Field_0 = record {
	start_index: uint8;
	stop_index: uint8;
};

type Range_Field_1 = record {
	start_index: uint16;
	stop_index: uint16;
}
  &byteorder = littleendian;

type Range_Field_2 = record {
	start_index: uint32;
	stop_index: uint32;
}
  &byteorder = littleendian;

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
# reserved
	RESPONSE = 0x81,
	UNSOLICITED_RESPONSE = 0x82,
	AUTHENTICATE_RESP = 0x83,
# reserved
};

%include dnp3-objects.pac
