# See the file "COPYING" in the main distribution directory for copyright.
#
# Analyzer for MySQL
#  - mysql-protocol.pac: describes the MySQL protocol messages
#  - mysql-analyzer.pac: describes the MySQL analyzer code

%include binpac.pac
%include zeek.pac

%extern{

namespace zeek::analyzer::mysql { class MySQL_Analyzer; }
namespace binpac { namespace MySQL { class MySQL_Conn; } }
using MySQLAnalyzer = zeek::analyzer::mysql::MySQL_Analyzer*;

#include "zeek/analyzer/protocol/mysql/MySQL.h"

#include "zeek/analyzer/protocol/mysql/events.bif.h"

%}

extern type MySQLAnalyzer;

analyzer MySQL withcontext {
	connection: MySQL_Conn;
	flow:       MySQL_Flow;
};

# Our connection consists of two flows, one in each direction.
connection MySQL_Conn(zeek_analyzer: MySQLAnalyzer) {
	upflow   = MySQL_Flow(true);
	downflow = MySQL_Flow(false);
};

%include mysql-protocol.pac

# Now we define the flow:
flow MySQL_Flow(is_orig: bool) {
	# There are two options here: flowunit or datagram.
	# flowunit = MySQL_PDU(is_orig) withcontext(connection, this);
	flowunit = MySQL_PDU(is_orig) withcontext(connection, this);
	# Using flowunit will cause the analyzer to buffer incremental input.
	# This is needed for &oneline and &length. If you don't need this, you'll
	# get better performance with datagram.
};

%include mysql-analyzer.pac
