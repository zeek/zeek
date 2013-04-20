%include binpac.pac
%include bro.pac

analyzer MySQL withcontext {
  connection: MySQL_Conn;
  flow:	      MySQL_Flow;
};

connection MySQL_Conn(bro_analyzer: BroAnalyzer) {
	upflow = MySQL_Flow(true);
	downflow = MySQL_Flow(false);
};

%include mysql-protocol.pac

flow MySQL_Flow(is_orig: bool) {
	flowunit = MySQLPDU(is_orig) withcontext(connection, this);
};
%include mysql-analyzer.pac