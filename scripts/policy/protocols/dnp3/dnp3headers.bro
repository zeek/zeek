### global defintion
type g_range_field : record {
	low: int;
	high: int;
};

global range_field_buf: table [count] of g_range_field; 
global g_cc_addr: addr;
global g_sub_addr: addr;
global num_obj_header: count = 0;
#num_obj_header = 0;

event dnp3_header_block(c: connection, is_orig: bool, start: count, len: count, ctrl: count, dest_addr: count, src_addr: count)
	{
        print fmt("dnp3tcp header. start: %x, length: %x, ctrl: %x, dest_addr: %x, src_addr: %x ", start, len, ctrl, dest_addr, src_addr);
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
	print fmt("dnp3 application request header: app_control: %x, fc: %x", app_control, fc);
	
        }
event dnp3_application_response_header(c: connection, is_orig: bool, app_control: count, fc: count)
        {
	print fmt("dnp3 application response header: app_control: %x, fc: %x", app_control, fc);
	#print hexdump(app_control);
        }
event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
        {
	local m_range_field_buf: table [count] of g_range_field;
	local m_num_obj_header: count = 0;
	local m_rf: g_range_field;

        print fmt("dnp3 object header is_orig: %d, obj_type: %x, qua_field: %x, number-of-item: %x, rf_high: %x, rf_low: %x ", is_orig, obj_type, qua_field, number, rf_high, rf_low);
	if(is_orig)
	{
		++num_obj_header;
		m_num_obj_header = 0;
		if(num_obj_header == 1)
			range_field_buf = m_range_field_buf;  # emtpy the table

		m_rf$low = rf_low;
		m_rf$high = rf_high;
		range_field_buf[num_obj_header]	= m_rf;
		print fmt("Debug Insert %d %x ", num_obj_header, range_field_buf[num_obj_header]$low);
		#m_range_field
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

        }
event dnp3_response_data_object(c: connection, is_orig: bool, data_value: count)
        {
        if(data_value != 0xff)
                print fmt("dnp3 response data object. data_value: %x ", data_value);
        }
#event dnp3_debug_byte(c: connection, is_orig: bool, debug: string)
#	{
#	print fmt ("debug byte ");
#	print hexdump(debug);
#	}
