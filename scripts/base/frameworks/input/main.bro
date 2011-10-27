
module Input;

export {
	type ReaderDescription: record {
		source: string;
		idx: any;
		val: any;
		destination: any;
	};
}

@load base/input.bif
