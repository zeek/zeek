%include binpac.pac
%include bro.pac

analyzer PE withcontext {
	connection: MockConnection;
	flow:       File;
};

connection MockConnection(bro_analyzer: BroFileAnalyzer) {
	upflow = File(0);
	downflow = File(0);
};

%include pe-file.pac

flow File(fsize: uint64) {
	flowunit = TheFile(fsize) withcontext(connection, this);
}
 
%include pe-analyzer.pac
