%include binpac.pac
%include bro.pac

analyzer PE withcontext {
	connection: MockConnection;
	flow:       File;
};

connection MockConnection(bro_analyzer: BroFileAnalyzer) {
	upflow = File;
	downflow = File;
};

%include pe-file.pac

flow File {
	flowunit = PE_File withcontext(connection, this);
}
 
%include pe-analyzer.pac
