# $Id:$
#
# This template code contributed by Kristin Stephens.

connection Dnp3_Conn(bro_analyzer: BroAnalyzer) {
	upflow = Dnp3_Flow(true);
	downflow = Dnp3_Flow(false);
};

flow Dnp3_Flow(is_orig: bool) {
	datagram  = Dnp3_PDU(is_orig) withcontext (connection, this);

	function get_dnp3_application_request_header(app_control: uint8, fc: uint8): bool
		%{
		if ( ::dnp3_application_request_header )
			{
			BifEvent::generate_dnp3_application_request_header(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), app_control, fc);
			}

		return true;
		%}
	function get_dnp3_object_header(obj_type: uint16, qua_field: uint8): bool
		%{
		if ( ::dnp3_object_header )
			{
			BifEvent::generate_dnp3_object_header(
				connection()->bro_analyzer(),
				connection()->bro_analyzer()->Conn(),
				is_orig(), obj_type, qua_field);
			}

		return true;
		%}


};

refine typeattr Dnp3_Application_Request_Header += &let {
        process_request: bool =  $context.flow.get_dnp3_application_request_header(application_control, function_code);
};

refine typeattr Object_Header += &let {
        process_request: bool =  $context.flow.get_dnp3_object_header(object_type_field, qualifier_field);
};









