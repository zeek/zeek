
module Input;

export {
	type ReaderDescription: record {
		source: string;
		idx: any;
		val: any &optional;
		destination: any &optional;
	};
}

@load base/input.bif
