### global defintion
type g_range_field : record {
	low: int;
	high: int;
};
type gSelObj : record{
	mObjType: int;
	mQuaField: int;	
};
global gSelObjBuf: table [count] of gSelObj;
global gNumSelObjType: count = 0;
global gNumSelQuaField: count = 0;
global gNumOpObj: count = 0;

global range_field_buf: table [count] of g_range_field; 
global g_cc_addr: addr;
global g_sub_addr: addr;
global num_obj_header: count = 0;
global solSeq: count = 16;
global reqFc: count = 0;
#global debug: bool = T;
global experiment: bool = T;
global a: table[count] of count = {
       [1] = 1,   [2] = 2,   [3] = 3,   [4] = 4,
       [5] = 5,   [6] = 6,   [7] = 7,   [8] = 8,
       [9] = 9,   [10] = 10, [11] = 11, [12] = 12,
       [13] = 13, [14] = 14, [15] = 15, [16] = 16,
   };

function iin_value(iin: count): bool{
	local mTempBit: count = 0;
	local index: count = 0;
	local loopIndex: count = 1;
	index = 0x1;
	
	for ( i in a ){
		mTempBit = iin % (2*index);
		mTempBit = mTempBit / index;
		if(mTempBit == 1) { print fmt("ALERT IIN bit %d is set", loopIndex); }
		index = index * 2;
		++loopIndex;
	}

	return T;
}


event dnp3_header_block(c: connection, is_orig: bool, start: count, len: count, ctrl: count, dest_addr: count, src_addr: count)
	{
	print fmt("  ");
        print fmt("dnP3 addin header. start: %x, length: %x, ctrl: %x, dest_addr: %x, src_addr: %x ", start, len, ctrl, dest_addr, src_addr);
### verify the null response to certain request
	if(is_orig == F)
	{
		if( (reqFc == 0x02) && (len != 10) )
		{
			print fmt("ALERT  response of write is not NULL response");
		}
		if( (reqFc == 0x09) && (len != 10) )
		{
			print fmt("ALERT  response of freeze-clear is not null response");
		}
		if( (reqFc == 0x0B) && (len != 10) )
		{
			print fmt("ALERT  response of freeze-at-time is not null response");
		}
		if( ( (reqFc == 0x10) || (reqFc == 0x11) || (reqFc == 0x12) ) && (len != 10) )
		{
			print fmt("ALERT  response of applicatin-related operation is not null response");
		}
		if( ( (reqFc == 0x14) || (reqFc == 0x15) ) && (len != 10) )
		{
			print fmt("ALERT  response of enable/disable unsolicted is not null response");
		}
	}
### verify the null response to certain request
        }

event dnp3_data_block(c: connection, is_orig: bool, data: string, crc: count)
	{
	print fmt("dnp3tcp data block");
	print hexdump(data);
        print fmt("crc: %x", crc);
        }

event dnp3_pdu_test(c: connection, is_orig: bool, rest: string)
	{
	print fmt("dnp3tcp pdu");
	print hexdump(rest);
        }

event dnp3_application_request_header(c: connection, is_orig: bool, app_control: count, fc: count)
        {
	local mTempSeq: count = 0;
### verify function code value range
	if( fc >= 0x20 && fc <= 0x80 )
	{
		print fmt("ALERT, reqeust function code is out of range");
	}
### verify function code value range
### detect obsolete function code value
	if( fc == 0x0F)
	{
		print fmt("ALERT  initialize data code is obsolete");
	}
### detect obsolete function code value
### valide solSeq values; assign it if it is 0
	mTempSeq = app_control / 0x10;
	mTempSeq = app_control - mTempSeq * 0x10;
	if(experiment == T){
		solSeq = mTempSeq;
	}
	else{
		if(solSeq == 16){
			solSeq = mTempSeq;
		}
		else{
			if( ( ( (solSeq + 1 ) % 16) != mTempSeq) && (fc != 0) ){
				print fmt("ALERT  solicited sequence number abnormally");
			}
			if(fc != 0){  # confirm request does not increase sequence number
				++solSeq;
				solSeq = solSeq % 16;	
			}
		}
	}
	
### valide solSeq values; assign it if it is 0
### record fc; verify some group req fc code such as select and operate
	if( (fc == 0x04) && (reqFc != 0x03) )
	{
		print fmt("ALERT  operate is issued without select");
	}
	if( (reqFc == 0x03) && (fc != 0x04))
	{
		print fmt("ALERT  select is not followed by operate");
	}
	reqFc = fc; 
### record fc
 

        }

event dnp3_application_response_header(c: connection, is_orig: bool, app_control: count, fc: count, iin: count)
        {
	local mTempSeq : count = 0;
	print fmt("dnp3 application response header: app_control: %x, fc: %x, iin: %x", app_control, fc, iin);
### verify function code value range
	if( fc > 0x84 )
	{
		print fmt("ALERT, response function code is out of range");
	}
### verify function code value range

### verify iin2.6 and iin2.7 are zero 
	if( (iin / 0x4000) != 0 )
	{
		print fmt("ALERT  iin is out of range, %x", iin/0x4000);
	}
### !verify iin2.6 and iin2.7 are zero
### report error reflected in iin
	if(iin != 0){
		iin_value(iin);		
	}
### !report error reflected in iin
### verify solSeq values
	mTempSeq = app_control / 0x10;
	mTempSeq = app_control - mTempSeq * 0x10;

	if( (solSeq != 16) && (solSeq != mTempSeq) )
	{
		print fmt("ALERT  solicited sequence number abnormally");
		++solSeq;
		solSeq = solSeq % 16;
	}
### !verify solSeq values


        }

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
        {
	local m_range_field_buf: table [count] of g_range_field;
	local m_num_obj_header: count = 0;
	local m_rf: g_range_field;
	local mTemp: count = 0;
	local mTempOne: count = 0;
	#local emptyBuf: table [count] of int;
	local emptyBuf: table [count] of gSelObj;
	local mSelObjBuf: gSelObj;
	local mAuthChan: count = 2; # who issue auth chanllege, request of response
	
### verify that object group 60 only happens in request
	if( ((obj_type / 0x100) == 0x3C) && (is_orig != T  ) )	
	{
		print fmt("ALERT  group 60 happens in response ");
	}
### verify that object group 60 only happens in request
### verify that vartion 0 only happens in request
	mTemp = obj_type / 0x100;
	mTemp = obj_type - mTemp * 0x100;
	if( (mTemp == 0x0) && (is_orig != T  ) )	
	{
		print fmt("ALERT  group 60 happens in response ");
	}
### verify that varition 0 only happens in request
### verify that res field in Qualifier octet is always 0
	if( (qua_field / 0x80) != 0)
	{
		print fmt("ALERT  res field is not 0");
	}
### verify that res field in Qualifier octet is always 0
### verify that object prefix code in qualifier octet field can not be 7
	if( (qua_field / 0x10) == 7)
	{
		print fmt("ALERT  object prefix code is 7");
	}
### verify that object prefix code in qualifier octet field can not be 7
### verify that range specifier code is valid. Invalid values: A, C, D, E, F
	mTemp = qua_field / 0x10;
	mTemp = qua_field - mTemp * 0x10;
	if(mTemp == 0xA || mTemp >= 0xC )
	{
		print fmt("ALERT  range specifier code is invalid %x", mTemp);
	}
### verify that range specifier code is valid. Invalid values: A, C, D, E, F
### verify that qualifier codes are valid overall
	mTempOne = qua_field / 0x10;  #object prefix
	mTemp = qua_field - mTempOne * 0x10; # range specifier code
	if( (mTempOne == 0) && (mTemp >= 0xA) )
	{	
		print fmt("ALERT  qualifier octet is not valid %x%x", mTempOne, mTemp);
	}
	if( ((mTempOne >= 1) && (mTempOne <= 3)) && ( (mTemp < 7) || (mTemp > 9) )  )
	{
		print fmt("ALERT  qualifier octet is not valid %x%x", mTempOne, mTemp);
	}
	if( ((mTempOne >= 4) && (mTempOne <= 6)) && ( mTemp != 0xB)  )
	{
		print fmt("ALERT  qualifier octet is not valid %x%x", mTempOne, mTemp);
	}
### !verify that qualifier codes are valid overall
### verify that range field codes are valid overall

	if(is_orig)
	{
		++num_obj_header;
		m_num_obj_header = 0;
		if(num_obj_header == 1)
			range_field_buf = m_range_field_buf;  # emtpy the table

		m_rf$low = rf_low;
		m_rf$high = rf_high;
		range_field_buf[num_obj_header]	= m_rf;
	}
	else
	{
		num_obj_header = 0;
		++m_num_obj_header;
		
		if( ( (range_field_buf[m_num_obj_header]$low) != rf_low  ) && 
			(  (range_field_buf[m_num_obj_header]$low) != 0xffff ) &&			
			(  (range_field_buf[m_num_obj_header]$high) != rf_high) && 
			(  (range_field_buf[m_num_obj_header]$high) != 0xffff) 	)
		{
			print fmt("Hui Lin alert unmatched range field %d, %d  %x  %x", num_obj_header, m_num_obj_header, range_field_buf[m_num_obj_header]$low, rf_low);
		}
	}
### !verify that range field codes are valid overall

### verify that select and operate contains same objects and in order
	if( (reqFc == 0x03) && (is_orig == T))
	{
		++gNumSelObjType;
		if(gNumSelObjType == 1)
		{
			gSelObjBuf=emptyBuf;
		}
		mSelObjBuf$mObjType = obj_type;
		mSelObjBuf$mQuaField = qua_field;
		gSelObjBuf[gNumSelObjType] = mSelObjBuf;

		gNumOpObj = 0;
	}
	
	
	if((reqFc == 0x04) && (is_orig == T ) )
	{
		++gNumOpObj;
		if( gSelObjBuf[gNumOpObj]$mObjType != obj_type)
		{
			print fmt("ALERT  operate contains different qualifier field");
		}
		if( gSelObjBuf[gNumOpObj]$mQuaField != qua_field)
		{
			print fmt("ALERT  operate contains different prefix");
		}		
		gNumSelObjType = 0;
	}
### !verify that select and operate contains same objects and in order

### verify that some obj type can only be called by certain function code
	if( (obj_type == 0x0c01) && ((reqFc < 0x03) || (reqFc > 0x06)))
	{
		print fmt("ALERT  CROB is called by invalid function code");
	}
	if( (obj_type == 0x0c02) && ((reqFc < 0x02) || (reqFc > 0x06)))
	{
		print fmt("ALERT  PCB is called by invalid function code");
	}
### !verify that some obj type can only be called by certain function code
### verify that some qualifier field can only be called by certain function code
	if( (reqFc >= 0x10) && (reqFc <= 0x12 ))
	{
		if( (qua_field != 0x06) && (qua_field != 0x5B) )
		{
			print fmt("ALERT qualifier field is not valid in application related operation");
		}	
	}
### !verify that some qualifier field can only be called by certain function code
### cold and warm restart respond with g52v1 or g52v2
	if( is_orig == F)
	{
		if( ( (reqFc == 0x0D) || (reqFc == 0x0E) ) && (obj_type != 0x3401) && (obj_type != 0x3402) ) 
		{
			print fmt("ALERT  response of cold warm start is not valid");
		}
	}
### !cold and warm restart respond with g52v1 or g52v2
### save configuration respond with g52v1 or g52v2
	if( is_orig == F)
	{
		if(  (reqFc == 0x0D) && (obj_type != 0x3401) && (obj_type != 0x3402) ) 
		{
			print fmt("ALERT  response of save configuration is not valid");
		}
	}
### !save configuration respond with g52v1 or g52v2

### validate that some request does not contain objects
	if(is_orig == T)
	{
		if( (reqFc == 0x17) && (number != 0) )	
		{
			print fmt("ALERT  request of delay measurement does not have zero objects");
		}
	}
### !validate that some request does not contain objects
### delay measurement: response contains single g52v2 object
	if( is_orig == F)
	{
		if(  (reqFc == 0x17) && (obj_type != 0x3402) && (number != 1) ) 
		{
			print fmt("ALERT  response of delay measurement is not valid");
		}
	}
### !delay measurement: response contains single g52v2 object
### file open delete: g70v3 in the request
	if( (is_orig == T) && ( (reqFc == 0x19) || (reqFc == 0x1B) ) )
	{
		if(obj_type != 0x4603)
		{
			print fmt("ALERT  request of open file and delete file is not valid");
		}
	}
### !file open delete: g70v3 in the request
### file open delete: g70v4 in the response
	if( (is_orig == F) && ( (reqFc == 0x19) || (reqFc == 0x1B) || (reqFc == 0x1A) || (reqFc == 0x1E)  ) )
	{
		if(obj_type != 0x4604)
		{
			print fmt("ALERT  response of open close delete abort file is not valid");
		}
	}
### !file open delete: g70v4 in the response
### get file: g70v7 in the request
	if( (is_orig == T) &&  (reqFc == 0x1C) )
	{
		if(obj_type != 0x4607)
		{
			print fmt("ALERT  request of get file info is not valid");
		}
	}
### !get file: g70v7 in the request

### authenticate file: g70v2 in the request
	if( (is_orig == T) &&  (reqFc == 0x1D) )
	{
		if(obj_type != 0x4602)
		{
			print fmt("ALERT  request of authenticate file is not valid");
		}
	}
### !authenticate file: g70v2 in the request

### activate configuration: g70v8 and g110 are in the request
	mTemp = obj_type / 0x100;
	if( (is_orig == T) && (reqFc == 0x1F))
	{	
		if( ( obj_type != 0x4608 ) && ( mTemp != 0x6E) )
		{
			print fmt("ALERT  request of activate configuration is not valid");
		}
	}
### !activate configuration: g70v8 and g110 are in the request

### activate configuration: g91v1 are in the response
	if( (is_orig == F) && (reqFc == 0x1F))
	{	
		if(  obj_type != 0x5B01 )
		{
			print fmt("ALERT  response of activate configuration is not valid");
		}
	}
### !activate configuration: g91v1 are in the response
### not support very well for several object type
	mTemp = obj_type / 0x100;
	if( (obj_type == 0x5101) || 
		(obj_type == 0x5603) || (obj_type == 0x5701) || (obj_type == 0x5801) ||
		(mTemp == 0x64)){
		print fmt("ALERT  objects are not supprted very well so far");
	}
### !not support very well for several object type
### verify authentication objects
	if(mTemp == 0x78){
		if( (qua_field != 0x5b) || (number != 1) ) {
			print fmt("ALERT  only authentication object is needed");
		}
	}
	if( mAuthChan != 2){
		mAuthChan = 2;
		if(obj_type != 0x7802) print fmt("ALERT  response of authentication chanllege is not valid");
	}
	if(obj_type == 0x7801){
		mAuthChan = (is_orig? 1 : 0);	
	}
### !verify authentication objects


        }

event dnp3_object_prefix(c: connection, is_orig: bool, prefix_value: count)
	{
	print fmt("dnp3 object prefix %x ", prefix_value);
	}
event dnp3_response_data_object(c: connection, is_orig: bool, data_value: count)
        {
        if(data_value != 0xff)
                print fmt("dnp3 response data object. data_value: %x ", data_value);
        }
event dnp3_debug_byte(c: connection, is_orig: bool, debug: string)
	{
	print fmt ("ALERT  debug byte ");
	print hexdump(debug);
	}
