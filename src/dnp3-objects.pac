##### move from dnp3-protocol.pac
type Request_Data_Object(function_code: uint8, qualifier_field: uint8, object_type_field: uint16) = record {
	prefix: case ( qualifier_field & 0xf0 ) of {
                0x00 -> none: empty &check(qualifier_field == 0x01 ||
                                                qualifier_field == 0x02 ||
                                                qualifier_field == 0x03 ||
                                                qualifier_field == 0x04 ||
                                                qualifier_field == 0x05 ||
                                                qualifier_field == 0x06 ||
                                                qualifier_field == 0x07 ||
                                                qualifier_field == 0x08 ||
                                                qualifier_field == 0x09 );
                0x10 -> prefix8: uint8 &check(qualifier_field == 0x17 ||
                                                qualifier_field == 0x18 ||
                                                qualifier_field == 0x19 );
                0x20 -> prefix16: uint16 &check(qualifier_field == 0x27 ||
                                                qualifier_field == 0x28 ||
                                                qualifier_field == 0x29 );
                0x30 -> prefix32: uint32 &check(qualifier_field == 0x37 ||
                                                qualifier_field == 0x38 ||
                                                qualifier_field == 0x39 );
                0x40 -> object_size8: uint8 &check(qualifier_field == 0x4B);
                0x50 -> object_size16: uint16 &check(qualifier_field == 0x5B);
                0x60 -> object_size32: uint32 &check(qualifier_field == 0x6B);
	 	default -> unknownprefix: empty;
        };
	data: case (object_type_field) of {
	# binary input	
		0x0100 -> bi_default: empty;
		0x0101 -> bi_packed: empty;
		0x0102 -> bi_flag: empty;
	# binary output command
		0x0c01 -> bocmd_CROB: CROB &check (function_code == SELECT || function_code == OPERATE ||
                                                        function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR );
		0x0c02 -> bocmd_PCB: PCB &check (function_code == SELECT || function_code == OPERATE ||
                                                        function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR || function_code == WRITE );
		0x0c03 -> bocmd_PM: uint8;
	# counter ; g20
		0x1400 -> counter_default: empty;
		0x1401 -> counter_32_wflag: empty;
		0x1402 -> counter_16_wflag: empty;
		0x1403 -> counter_32_wflag_delta: empty &check (0); # obsolete situation; generate warning
		0x1404 -> counter_16_wflag_delta: empty &check (0); # obsolete situations; generate warning
		0x1405 -> counter_32_woflag: empty;
		0x1406 -> counter_16_woflag: empty;
		0x1407 -> counter_32_woflag_delta: empty &check (0); # obsolete	
		0x1408 -> counter_16_woflag_delta: empty &check (0); # obsolete		
	# frozen counter ; g21
		0x1500 -> f_counter_default: empty;
		0x1501 -> f_counter_32_wflag: empty;
		0x1502 -> f_counter_16_wflag: empty;
		0x1503 -> f_counter_32_wflag_delta: empty &check (0); # obsolete situation; generate warning
		0x1504 -> f_counter_16_wflag_delta: empty &check (0); # obsolete situations; generate warning
		0x1505 -> f_counter_32_wflag_time: empty;
		0x1506 -> f_counter_16_wflag_time: empty;
		0x1507 -> f_counter_32_wflag_time_delta: empty &check (0); # obsolete	
		0x1508 -> f_counter_16_wflag_time_delta: empty &check (0); # obsolete		
		0x1509 -> f_counter_32_woflag: empty;
		0x150a -> f_counter_16_woflag: empty;
		0x150b -> f_counter_32_woflag_delta: empty &check (0); # obsolete
		0x150c -> f_counter_16_woflag_delta: empty &check (0); # obsolete
	#analog input
		0x1e00 -> ai_default: empty;
		0x1e01 -> ai_32_wflag: empty;
                0x1e02 -> ai_16_wflag: empty;
                0x1e03 -> ai_32_woflag: empty;
                0x1e04 -> ai_16_woflag: empty;
                0x1e05 -> ai_sp_wflag: empty;
                0x1e06 -> ai_dp_wflag: empty;
	#frozen analog input g31
		0x1f00 -> f_ai_default: empty;
		0x1f01 -> f_ai_32_wflag: empty;
                0x1f02 -> f_ai_16_wflag: empty;
                0x1f03 -> f_ai_32_wtime: empty;
                0x1f04 -> f_ai_16_wtime: empty;
                0x1f05 -> f_ai_32_woflag: empty;
                0x1f06 -> f_ai_16_woflag: empty;
                0x1f07 -> f_ai_sp_wflag: empty;
                0x1f08 -> f_ai_dp_wflag: empty;
	#analog input event
		0x2000 -> aie_default: empty;
		0x2001 -> ai32wotime: empty;
		0x2002 -> ai16wotime: empty;
		0x2003 -> ai32wtime:  empty;
                0x2004 -> ai16wtime:  empty;
                0x2005 -> aispwotime: empty;
                0x2006 -> aidpwotime: empty;
                0x2007 -> aispwtime:  empty;
                0x2008 -> aidpwtime:  empty;
	# time data interval data object g50
		0x3200 -> time_default: empty;
		0x3201 -> time_abs: empty;
		0x3202 -> time_interval: AbsTimeInterval;  
		0x3203 -> time_abs_last: empty;
		0x3C01 -> class0data: empty &check(object_header.qualifier_field == 0x06);
		#0x3C02 -> class1data: uint8 &check(object_header.qualifier_field == 0x06);
		0x3C02 -> class1data: empty &check(object_header.qualifier_field == 0x06 || 
							object_header.qualifier_field == 0x07 || object_header.qualifier_field == 0x08);
		0x3C03 -> class2data: empty &check(object_header.qualifier_field == 0x06 || 
							object_header.qualifier_field == 0x07 || object_header.qualifier_field == 0x08);
		0x3C04 -> class3data: empty &check(object_header.qualifier_field == 0x06 || 
							object_header.qualifier_field == 0x07 || object_header.qualifier_field == 0x08);
	# file control g70
		0x4601 -> file_control_id: File_Control_ID &check(0);
		0x4602 -> file_control_auth: File_Control_Auth_Wrap(function_code); 
		0x4603 -> file_control_cmd: File_Control_Cmd &check( file_control_cmd.op_mode == 0 || file_control_cmd.op_mode == 1 || 
							  file_control_cmd.op_mode == 2 || file_control_cmd.op_mode == 3 );
		0x4604 -> file_control_cmd_status: File_Control_Cmd_Status_Wrap(function_code);  # example shown in P66
		0x4605 -> file_trans: File_Transport;
		0x4606 -> file_trans_status: File_Transport_Status;	
		0x4607 -> file_desc: File_Desc_Wrap(function_code);
	# application identification object g90
		0x5A01 -> app_id: App_Id(qualifier_field, object_size16);
	#	default -> unknown: bytestring &restofdata &check(0);
		default -> unmatched: Default_Wrap(object_type_field);
	};	
};


type Response_Data_Object(function_code: uint8, qualifier_field: uint8, object_type_field: uint16) = record {
	prefix: case (qualifier_field & 0xf0 ) of {
		0x00 -> none: empty &check(qualifier_field == 0x01 ||
						qualifier_field == 0x02 ||
						qualifier_field == 0x03 ||
						qualifier_field == 0x04 ||
						qualifier_field == 0x05 ||	
						qualifier_field == 0x06 ||
						qualifier_field == 0x07 ||
						qualifier_field == 0x08 ||
						qualifier_field == 0x09 );
		0x10 -> prefix8: uint8 &check(qualifier_field == 0x17 || 
						qualifier_field == 0x18 ||
						qualifier_field == 0x19 );
		0x20 -> prefix16: uint16 &check(qualifier_field == 0x27 ||
                                                qualifier_field == 0x28 ||
                                                qualifier_field == 0x29 );
		0x30 -> prefix32: uint32 &check(qualifier_field == 0x37 ||
                                                qualifier_field == 0x38 ||
                                                qualifier_field == 0x39 );
		0x40 -> object_size8: uint8 &check(qualifier_field == 0x4B);
		0x50 -> object_size16: uint16 &check(qualifier_field == 0x5B);
		0x60 -> object_size32: uint32 &check(qualifier_field == 0x6B);
		default -> unknownprefix: empty;
	};
	data: case (object_type_field) of {
		0x0101 -> biwoflag: uint8;  # warning: returning integer index?
		0x0102 -> biwflag: uint8;  # warning: only flag?
		
		0x0a01 -> bowoflag:  uint8;  # warning: returning integer index?	
		0x0a02 -> bowflag: uint8;  # warning: only flag?
	# binary output command
                0x0c01 -> bocmd_CROB: CROB &check (function_code == SELECT || function_code == OPERATE ||
                                                        function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR );
                0x0c02 -> bocmd_PCB: PCB &check (function_code == SELECT || function_code == OPERATE ||
                                                        function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR || function_code == WRITE );
		0x0c03 -> bocmd_PM: uint8;
		
		0x1e01 -> ai_32_wflag: AnalogInput32wFlag;
                0x1e02 -> ai_16_wflag: AnalogInput16wFlag;
                0x1e03 -> ai_32_woflag: AnalogInput32woFlag;
                0x1e04 -> ai_16_woflag: AnalogInput16woFlag;
                0x1e05 -> ai_sp_wflag: AnalogInputSPwFlag;
                0x1e06 -> ai_dp_wflag: AnalogInputDPwFlag;
		
		0x2001 -> ai32wotime: AnalogInput32woTime;
		0x2002 -> ai16wotime: AnalogInput16woTime;
		0x2003 -> ai32wtime:  AnalogInput32wTime;
		0x2004 -> ai16wtime:  AnalogInput16wTime;
		0x2005 -> aispwotime: AnalogInputSPwoTime;
		0x2006 -> aidpwotime: AnalogInputDPwoTime;
		0x2007 -> aispwtime:  AnalogInputSPwTime;
		0x2008 -> aidpwtime:  AnalogInputDPwTime;
	# file control g70
		0x4601 -> file_control_id: File_Control_ID &check(0);
		0x4602 -> file_control_auth: File_Control_Auth &check(file_control_auth.usr_name_size == 0 && file_control_auth.pwd_size == 0);
		0x4603 -> file_control_cmd: File_Control_Cmd &check(file_control_cmd.name_size == 0 && 
							( file_control_cmd.op_mode == 0 || file_control_cmd.op_mode == 1 || 
							  file_control_cmd.op_mode == 2 || file_control_cmd.op_mode == 3) );
		0x4604 -> file_control_cmd_status: File_Control_Cmd_Status_Wrap(function_code);
		default -> unkonwndata: Debug_Byte &check(0); 
	};
}
  &let{
	data_value: uint8 = case (object_type_field) of {  # this data_value is used for the Bro Event
		0x0101 -> biwoflag;
		0x0102 -> biwflag;
		0x0a01 -> bowoflag;
		0x0a02 -> bowflag;
		default -> 0xff;		
	};
  }
;


######
# this Default_Wrap is created when dealing with g110. Only Group type matters and variations can be all. So too much coding
type Default_Wrap(obj_type: uint32) = record {
	unresolved: case (obj_type & 0xFF00) of {
		0x6E00 -> oct_str: bytestring &length = (obj_type & 0x00FF) ;
		default -> unknown: bytestring &restofdata;
	};
};

# contains different objects format
# corresponding to the DNP3Spec-V6-Part2-Objects 

# g12v1 group: 12; variation: 1
type CROB = record{
	control_code: uint8 &check ( (control_code & 0xCF) == 0x00 || (control_code & 0xCF) == 0x01 || (control_code & 0xCF) == 0x03 || (control_code & 0xCF) == 0x04 || 
					(control_code & 0xCF) == 0x41 || (control_code & 0xCF) == 0x81  );
	count: uint8;
	on_time: uint32;
	off_time: uint32;
	status_code: uint8;  # contains the reserved bit
} &byteorder = littleendian;
# g12v2; same as g12v1
type PCB = record{
	control_code: uint8 &check ( (control_code & 0xCF) == 0x00 || (control_code & 0xCF) == 0x01 || (control_code & 0xCF) == 0x03 || (control_code & 0xCF) == 0x04 || 
					(control_code & 0xCF) == 0x41 || (control_code & 0xCF) == 0x81  );
	count: uint8;
	on_time: uint32;
	off_time: uint32;
	status_code: uint8;  # contains the reserved bit
} &byteorder = littleendian;

# g20v1; group: 20, variation 1
type Counter32wFlag = record{
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;
# g20v2
type Counter16wFlag = record{
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;
# g20v3 and g20v4 are obsolete
# g20v5
type Counter32woFlag = record{
	count_value: uint32;
} &byteorder = littleendian;
# g20v6
type Counter16woFlag = record{
	count_value: uint16;
} &byteorder = littleendian;
# g20v7 and g20v8 are obsolete

# g21v1
type FrozenCounter32wFlag = record{
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;
# g21v2
type FrozenCounter16wFlag = record{
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;
# g21v3 and g21v4 are obsolete
# g21v5
type FrozenCounter32wFlagTime = record{
	flag: uint8;
	count_value: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g21v6
type FrozenCounter16wFlagTime = record{
	flag: uint8;
	count_value: uint16;
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g21v7 and g21v8 are obsolete
# g21v9
type FrozenCounter32woFlag = record{
        count_value: uint32;
} &byteorder = littleendian;
# g21v10
type FrozenCounter16woFlag = record{
        count_value: uint16;
} &byteorder = littleendian;
# g21v11 and g21v12 are obsolete


# group: 30; variation: 1
type AnalogInput32wFlag = record{
        flag: uint8;
        value: int32;
} &byteorder = littleendian;

# group: 30; variation: 2
type AnalogInput16wFlag = record{
        flag: uint8;
        value: int16;
} &byteorder = littleendian;

# group: 30; variation: 3
type AnalogInput32woFlag = record{
        value: int32;
} &byteorder = littleendian;

# group: 30; variation: 4
type AnalogInput16woFlag = record{
        value: int16;
} &byteorder = littleendian;

# group: 30; variation: 5; singple precision 32 bit
type AnalogInputSPwFlag = record{
        flag: uint8;
        value: uint32;
} &byteorder = littleendian;

# group: 30; variation: 6; double precision 64 bit
type AnalogInputDPwFlag = record{
        flag: uint8;
        value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# g31v1
type FrozenAnalogInput32wFlag = record{
        flag: uint8;
        frozen_value: int32;
} &byteorder = littleendian;
# g31v2
type FrozenAnalogInput16wFlag = record{
        flag: uint8;
        frozen_value: int16;
} &byteorder = littleendian;
# g31v3
type FrozenAnalogInput32wTime = record{
	flag: uint8;
        frozen_value: int32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g31v4
type FrozenAnalogInput16wTime = record{
        flag: uint8;
	frozen_value: int16;
	time48: bytestring &length = 6;
}  &byteorder = littleendian;
# g31v5
type FrozenAnalogInput32woFlag = record{
        frozen_value: int32;
} &byteorder = littleendian;
# g31v6
type FrozenAnalogInput16woFlag = record{
        frozen_value: uint16;
} &byteorder = littleendian;
# g31v7
type FrozenAnalogInputSPwFlag = record{
        flag: uint8;
        frozen_value: uint32;
} &byteorder = littleendian;
# g31v8
type FrozenAnalogInputDPwFlag = record{
        flag: uint8;
        frozen_value_low: uint32;
        frozen_value_high: uint32;
} &byteorder = littleendian;

# group: 32; variation: 1
type AnalogInput32woTime = record{
	flag: uint8;
	value: uint32;
} &byteorder = littleendian;

# group: 32; variation: 2
type AnalogInput16woTime = record{
	flag: uint8;
	value: uint16;
} &byteorder = littleendian;

# group: 32; variation: 3
type AnalogInput32wTime = record{
	flag: uint8;
	value: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 4
type AnalogInput16wTime = record{
	flag: uint8;
	value: uint16;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 5; singple precision 32 bit
type AnalogInputSPwoTime = record{
	flag: uint8;
	value: uint32;
} &byteorder = littleendian;

# group: 32; variation: 6; double precision 64 bit
type AnalogInputDPwoTime = record{
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# group: 32; variation: 7
type AnalogInputSPwTime = record{
	flag: uint8;
	value: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 8
type AnalogInputDPwTime = record{
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g50v1
type AbsTime = record {
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g50v2
type AbsTimeInterval = record {
	time48: bytestring &length = 6;
	interval: uint32;
} &byteorder = littleendian;

# g50v3
type Last_AbsTime = record {
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g70v1
type Record_Obj = record {
	record_size: uint16;
	record_oct: bytestring &length = record_size;
} &byteorder = littleendian;
type File_Control_ID = record {
	name_size: uint16;
	type_code: uint8;
	attr_code: uint8;
	start_rec: uint16;
	end_rec: uint16;
	file_size: uint32;
	time_create: bytestring &length = 6;
	permission: uint16 &check ( (permission & 0xFE00 ) == 0x0000); 
	file_id: uint32;
	owner_id: uint32;
	group_id: uint32;
	function_code: uint8;
	status_code: uint8;
	file_name: bytestring &length = name_size;
	records: Record_Obj[];
} &byteorder = littleendian;
# g70v2
type File_Control_Auth_Wrap(fc: uint8) = record {
	data: case(fc) of {
		AUTHENTICATE_FILE -> auth_file: File_Control_Auth &check(auth_file.auth_key == 0) ;
		default -> null: empty;
	};
};
type File_Control_Auth = record {
	usr_name_offset: uint16;
	usr_name_size: uint16;
	pwd_offset: uint16;
	pwd_size: uint16;
	auth_key: uint32;
	usr_name: bytestring &length = usr_name_size;
	pwd: bytestring &length = pwd_size;
} &byteorder = littleendian;
# g70v3
type File_Control_Cmd_Wrap(function_code: uint8) = record {
	data_obj: case (function_code) of {
		OPEN_FILE -> fc_cmd_open: File_Control_Cmd;
		DELETE_FILE -> fc_cmd_del: File_Control_Cmd &check( fc_cmd_del.op_mode == 0 &&  fc_cmd_del.name_size == 0 && fc_cmd_del.time_create == 0x0);
		default -> null: empty;
	};
	
};
type File_Control_Cmd = record {
	name_offset: uint16;
	name_size: uint16;
	time_create: bytestring &length = 6;
	permission: uint16 &check ( (permission & 0xFE00 ) == 0x0000); 
	auth_key: uint32;
	file_size: uint32;
	op_mode: uint16;
	max_block_size: uint16;
	req_id: uint16;
	file_name: bytestring &length = name_size;
} &byteorder = littleendian;
# g70v4
type File_Control_Cmd_Status_Wrap(function_code: uint8) = record{
	data_obj: case (function_code) of {
		ABORT_FILE -> abort: File_Control_Cmd_Status &check(abort.file_size == 0 && abort.max_block_size ==0 && abort.status_code ==0 );
		RESPONSE -> fc_cmd_status: File_Control_Cmd_Status;
		default -> null: empty;
	};
}; 
type File_Control_Cmd_Status = record {
	file_handle: uint32;
	file_size: uint32;
	max_block_size: uint16;
	req_id: uint16 ; 
	status_code: uint8;
	opt_text: bytestring &restofdata;
} &byteorder = littleendian;
# g70v5
type File_Transport = record {
	file_handle: uint32;
	block_num: uint32;
	file_data: bytestring &restofdata;
} &byteorder = littleendian;
# g70v6
type File_Transport_Status = record {
	file_handle: uint32;
	block_num: uint32;
	status: uint8;
	file_data: bytestring &restofdata;
} &byteorder = littleendian;
# g70v7
type File_Desc_Wrap(function_code: uint8) = record {
	data: case(function_code) of {
		GET_FILE_INFO -> get_file_info: File_Desc &check(get_file_info.type ==0 && get_file_info.f_size == 0 && get_file_info.time_create_low == 0 && get_file_info.time_create_high == 0
									 && get_file_info.permission == 0);
	};
} &byteorder = littleendian;
type File_Desc = record {
	name_offset: uint16;
	name_size: uint16;
	type: uint16;
	f_size: uint32;
	time_create_low: uint32;
	time_create_high: uint16;
	permission: uint16 &check ( (permission & 0xFE00 ) == 0x0000);
	req_id: uint16; 
	f_name: bytestring &length = name_size;
} &byteorder = littleendian;
# g70v8
type File_Spec_Str = record {
	f_spec: bytestring &restofdata;
} &byteorder = littleendian;


# g90v1
type App_Id(qualifier_field: uint8, object_size16: uint16) = record {
	app_id: case (qualifier_field) of {
		0x5B -> app_name: bytestring &length = object_size16;
		0x06 -> all_app: empty;
		default -> illegal: empty;
	};
} &byteorder = littleendian;
