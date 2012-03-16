#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
sdfkh:KH;fdkncv;ISEUp34:Fkdj;YVpIODhfDF
DSF"DFKJ"SDFKLh304yrsdkfj@#(*U$34jfDJup3UF
q3r3057fdf
sdfs\d

dfsdf
sdf
3rw43wRRERLlL#RWERERERE.
@TEST-END-FILE


module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string) {
	print description;
	print s;
}

event bro_init()
{
	Input::add_event([$source="input.log", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line]);
}
