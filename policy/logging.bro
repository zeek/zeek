
function Log_add_default_filter(id: Log_ID)
	{
	log_add_filter(id, [$name="default"]);
	}
	
function Log_remove_default_filter(id: Log_ID): bool
	{
	log_remove_filter(id, "default");
	}
