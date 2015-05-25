	function proc_client_hello(
					version : uint16, ts : double,
					client_random : bytestring,
					session_id : uint8[],
					cipher_suites16 : uint16[],
					cipher_suites24 : uint24[]) : bool
		%{
		if ( ! version_ok(version) )
			{
			bro_analyzer()->ProtocolViolation(fmt("unsupported client SSL version 0x%04x", version));
			bro_analyzer()->SetSkip(true);
			}
		else
			bro_analyzer()->ProtocolConfirmation();

		if ( ssl_client_hello )
			{
			vector<int>* cipher_suites = new vector<int>();
			if ( cipher_suites16 )
				std::copy(cipher_suites16->begin(), cipher_suites16->end(), std::back_inserter(*cipher_suites));
			else
				std::transform(cipher_suites24->begin(), cipher_suites24->end(), std::back_inserter(*cipher_suites), to_int());

			VectorVal* cipher_vec = new VectorVal(internal_type("index_vec")->AsVectorType());
			for ( unsigned int i = 0; i < cipher_suites->size(); ++i )
				{
				Val* ciph = new Val((*cipher_suites)[i], TYPE_COUNT);
				cipher_vec->Assign(i, ciph);
				}

			BifEvent::generate_ssl_client_hello(bro_analyzer(), bro_analyzer()->Conn(),
							version, ts, new StringVal(client_random.length(),
							(const char*) client_random.data()),
							to_string_val(session_id),
							cipher_vec);

			delete cipher_suites;
			}

		return true;
		%}

