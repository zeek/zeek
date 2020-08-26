%include binpac.pac
%include zeek.pac

analyzer PE withcontext {
	connection: MockConnection;
	flow:       File;
};

connection MockConnection(zeek_analyzer: ZeekFileAnalyzer) {
	upflow = File;
	downflow = File;
};

%include pe-file.pac

flow File {
	flowunit = PE_File withcontext(connection, this);
}

%include pe-analyzer.pac
