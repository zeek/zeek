%include binpac.pac
%include bro.pac

analyzer ZIP_File withcontext {
	analyzer:   ZIP_File_Analyzer;
	flow:       Flow;
};

analyzer ZIP_File_Analyzer(bro_analyzer: BroFileAnalyzer) {
	downflow = Flow;
	upflow   = Flow;
};

%include zip-file.pac

flow Flow {
	flowunit = Files withcontext(connection, this);
};

%include zip-analyzer.pac
