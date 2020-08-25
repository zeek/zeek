
%include binpac.pac
%include zeek.pac

analyzer Unified2 withcontext {
	analyzer:   Unified2_Analyzer;
	flow:       Flow;
};

analyzer Unified2_Analyzer(zeek_analyzer: ZeekFileAnalyzer) {
	downflow = Flow;
	upflow   = Flow;
};

%include unified2-file.pac

flow Flow {
	flowunit = Record withcontext(connection, this);
};

%include unified2-analyzer.pac
