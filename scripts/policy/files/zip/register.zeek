##! Registers the ZIP analyzer to handle the application/zip mime type

event zeek_init()
	{
	Files::register_for_mime_type(Files::ANALYZER_ZIP, "application/zip");
	}
