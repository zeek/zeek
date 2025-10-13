@load protocols/ssl/decryption
@load base/protocols/http

event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "tls-keylog-file" )
		continue_processing();
	}
