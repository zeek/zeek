bool LLCDemo::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Rudimentary parsing of 802.2 LLC
	if ( 17 >= len )
		{
		packet->Weird("truncated_llc_header");
		return false;
		}

	if ( ! llc_demo_message )
		return true;

	auto dsap = data[14];
	auto ssap = data[15];
	auto control = data[16];

	event_mgr.Enqueue(llc_demo_message,
		val_mgr->Count(dsap),
		val_mgr->Count(ssap),
		val_mgr->Count(control));

	return true;
	}
