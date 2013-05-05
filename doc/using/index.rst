
=========
Using Bro
=========

Once Bro has been deployed in an environment and monitoring live traffic, it will, in its default configuration, begin to produce human-readable ASCII logs.  Each log file, produced by Bro's Logging Framework, is populated with organized, connection-oriented data.  As the logfiles are simple ASCII data, working with the data contained in them can be done from a command line terminal once you have been familiarized with the types of data you can find in each log file.

----------------------
Structure of Log Files
----------------------

The log files produced by Bro adhere to a structure as defined by the scripts that produced through which they were produced.  However, as each log file has been produced using the Logging Framework, there are similiarites shared by each log file.  Without breaking into the scripting aspect of Bro, a bird's eye view of how the log files are produced would progress as follows.  The script's author defines the kinds of data, such as the originating IP address or the duration of a connection, which will be used as fields in the log file.  The author then decides what behavior should generate a logfile entry, these behaviors can range from a connection having been completed or an HTTP GET method being issued by an orignator.  Once these behaviors have been observed, the data is passed to the Logging Framework which, in turn, adds an entry to the appropriate log file.  While the fields of the log entries can be modified by the user, the Logging Framework makes use of a header entry in each logfile to ensure that it remains self-describing.  This header entry can be see by running the unix utility ``head`` and outputting the first eight lines of the file.

.. btest:: framework_logging_factorial_02
   
   @TEST-EXEC: btest-rst-cmd head -8 ${TESTBASE}/Baseline/core.pppoe/conn.log

The sample above shows the header for a ``conn.log`` file which gives a detailed account of each connection as seen by Bro.  As you can see, header includes information such as what separators are being used for various types of data, what an empty field looks like and what an unset field looks like.  In this example, the default TAB separator is being used as the delimiter between fiends (\x09 is the tab character in hex).  It also lists the comma as the separator for set data, the string "(empty)" as the indicator for an empty field and the '-' character as the indicator for a field that hasn't been set.  The timestampe for when the file was created is included under "#open".  The header then goes on to detail the fields being listed in the file and the datatypes of those fields in #fields and #types respectively.  These two entries are often the two most significant points of interest as they detail not only the field name but the data type used.  

-------------
Using bro-cut
-------------

With an understanding of the structure of logfiles, we can start looking at using tools such as ``bro-cut`` to retrieve information from log files.  

