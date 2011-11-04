
module Input;

export {
	const default_reader = READER_ASCII &redef;

	type ReaderDescription: record {
		source: string;
		idx: any;
		val: any;
		destination: any;
		reader: Reader &default=default_reader;
	};

	type Filter: record {
		name: string; 
		## descriptive name. for later removal


		pred: function(typ: Input::Event, left: any, right: any): bool &optional;
		## decision function, that decides if an inserton, update or removal should really be executed
	};
		
}

@load base/input.bif
