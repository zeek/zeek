
refine connection Foo_Conn += {

	function Foo_data(msg: Foo_Message): bool
		%{
		StringVal* data = new StringVal(${msg.data}.length(), (const char*) ${msg.data}.data());
		BifEvent::generate_foo_message(bro_analyzer(), bro_analyzer()->Conn(), data);
		return true;
		%}

};

refine typeattr Foo_Message += &let {
	proc: bool = $context.connection.Foo_data(this);
};
