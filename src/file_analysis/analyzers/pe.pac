%include binpac.pac
%include bro.pac

analyzer PE withcontext {
	connection: File;
	flow:       Bytes;
};

connection File(bro_analyzer: BroFileAnalyzer) {
	upflow = Bytes(true);
	downflow = Bytes(false);
};

%include pe-file.pac

flow Bytes(is_orig: bool) {
	flowunit = TheFile() withcontext(connection, this);
}
 
%include pe-analyzer.pac
