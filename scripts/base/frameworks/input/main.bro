
module Input;

export {
	type Event: record {
		name: string;
		columns: any;
	};
}

@load base/input.bif
