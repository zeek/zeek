
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
}

@load base/input.bif
