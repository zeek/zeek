
refine connection Foo_Conn += {

	function Foo_data(msg: Foo_Message): bool
		%{
		auto data = zeek::make_intrusive<zeek::StringVal>(${msg.data}.length(), (const char*) ${msg.data}.data());
		zeek::BifEvent::enqueue_foo_message(bro_analyzer(), bro_analyzer()->Conn(), std::move(data));
		return true;
		%}

};

refine typeattr Foo_Message += &let {
	proc: bool = $context.connection.Foo_data(this);
};
