
=========
Using Bro
=========

Once Bro has been deployed in an environment and monitoring live traffic, it will, in its default configuration, begin to produce human-readable ASCII logs.  Each log file, produced by Bro's Logging Framework, is populated with organized, connection-oriented data.  As the log files are simple ASCII data, working with the data contained in them can be done from a command line terminal once you have been familiarized with the types of data that can be found in each log file.

----------------------
Structure of Log Files
----------------------

The log files produced by Bro adhere to a structure as defined by the scripts that produced through which they were produced.  However, as each log file has been produced using the Logging Framework, there are similarities shared by each log file.  Without breaking into the scripting aspect of Bro, a bird's eye view of how the log files are produced would progress as follows.  The script's author defines the kinds of data, such as the originating IP address or the duration of a connection, which will be used as fields in the log file.  The author then decides what behavior should generate a log file entry, these behaviors can range from a connection having been completed or an HTTP GET method being issued by an originator.  Once these behaviors have been observed, the data is passed to the Logging Framework which, in turn, adds an entry to the appropriate log file.  While the fields of the log entries can be modified by the user, the Logging Framework makes use of a header entry in each log file to ensure that it remains self-describing.  This header entry can be see by running the unix utility ``head`` and outputting the first eight lines of the file.

.. btest:: using_bro_cmd_line_01
   
   @TEST-EXEC: btest-rst-cmd head -8 ${TESTBASE}/Baseline/core.pppoe/conn.log

The sample above shows the header for a ``conn.log`` file which gives a detailed account of each connection as seen by Bro.  As you can see, header includes information such as what separators are being used for various types of data, what an empty field looks like and what an unset field looks like.  In this example, the default TAB separator is being used as the delimiter between fiends (\x09 is the tab character in hex).  It also lists the comma as the separator for set data, the string "(empty)" as the indicator for an empty field and the '-' character as the indicator for a field that hasn't been set.  The timestamp for when the file was created is included under "#open".  The header then goes on to detail the fields being listed in the file and the data types of those fields in #fields and #types respectively.  These two entries are often the two most significant points of interest as they detail not only the field name but the data type used.  Navigating through the different log files produced by Bro, often requires the use of different elements of the unix tool chain such as ``sed``, ``awk``, or ``grep`` and having the field definitions readily available will save the user some mental leg work.  The field names are also a key resource for using the ``bro-cut`` utility included with Bro.

-------------
Using bro-cut
-------------

The ``bro-cut`` utility can be used in place of other tools to build terminal commands that remain flexible and accurate independent of possible changes that can be made to the log file itself.  It accomplishes this by parsing the header in each file and allowing the user to refer to the specific columnar data available.  In contrast tools like ``awk`` require the user to refer to fields referenced by their position.  For example, the two commands listed below produce the same output given a default configuration of Bro.  

.. btest:: using_bro_bro_cut_01

   @TEST-EXEC: btest-rst-cmd awk \'{print \$3, \$4, \$5, \$6, \$9}\' ${TESTBASE}/Baseline/doc.manual.using_bro_sandbox_01/conn.log

.. btest:: using_bro_bro_cut_02

   @TEST-EXEC: cat ${TESTBASE}/Baseline/doc.manual.using_bro_sandbox_01/conn.log | btest-rst-cmd bro-cut id.orig_h id.orig_p id.resp_h duration 


While the output is similar, the advantages to using bro-cut over awk lay in that,  while awk is flexible and powerful, ``bro-cut`` was specifically designed to work with log files.  Firstly, the ``bro-cut`` output includes only the log file entries, while the ``awk`` output includes the header parts of the log file, which would require the user to use a secondary utility to suppress those lines.  Secondly, since ``bro-cut`` uses the field descriptors to identify and extract data, it allows for flexibility independent of the format and contents of the log file.  It's not uncommon for a Bro configuration to add extra fields to various log files as required by the environment.  In this case, the fields in the ``awk`` command would have to be altered to compensate for the new position whereas the ``bro-cut`` output would not change.

As you may have noticed, the command for ``bro-cut`` uses the output redirection through the ``cat`` command and ``|`` operator.  Whereas tools like ``awk`` allow you to indicate the log file as a command line option, bro-cut only takes input through redirection such as ``|`` and ``<``.  There are a couple of ways to direct log file data into ``bro-cut``, each dependent upon the type of log file you're processing.  A caveat of its use, however, is that the 8 lines of header data must be present.  In its default setup, Bro will rotate log files on an hourly basis, moving the current log file into a directory with format ``YYYY-MM-DD`` and gzip compressing the file with a file format that includes the log file type and time range of the file.  In the case of processing a compressed log file you simply adjust your command line tools to use the complementary z* versions of commands such as cat (``zcat``), ``grep`` (``zgrep``), and ``head`` (``zhead``).

.......................
Working with timestamps
.......................

The ``bro-cut`` accepts the flag ``-d`` to convert the epoch time values in the log files to human-readable format.  The following command includes the human readable time stamp, the unique identifier and the HTTP host and HTTP uri as parsed from the ``http.log`` file.  

.. btest:: using_bro_bro_cut_time_01

   @TEST-EXEC: btest-rst-cmd bro-cut -d ts uid host uri < ${TESTBASE}/Baseline/doc.manual.using_bro_sandbox_01/http.log

Often times log files from multiple sources are stored in UTC time to allow easy correlation.  Converting the timestamp from a log file to UTC can be accomplished with the ``-u`` command.  

.. btest:: using_bro_bro_cut_time_02

   @TEST-EXEC: btest-rst-cmd bro-cut -u ts uid host uri < ${TESTBASE}/Baseline/doc.manual.using_bro_sandbox_01/http.log

The default time format when using the ``-d`` or ``-u`` is the ``strftime`` format string %Y-%m-%dT%H:%M:%S%z which results in a string with year, month, day of month, followed by hour, minutes, seconds and the timezone offset.  The default ``strftime`` can be altered by using the ``-D`` and ``-U`` flags. For example, to format the timestamp in the US-typical "Middle Endian" you could use a format string of: %d-%m-%YT%H:%M:%S%z

.. btest:: using_bro_bro_cut_time_03

   @TEST-EXEC: btest-rst-cmd bro-cut -D %d-%m-%YT%H:%M:%S%z ts uid host uri < ${TESTBASE}/Baseline/doc.manual.using_bro_sandbox_01/http.log

----------------------
Working with Log Files
----------------------

As Bro runs, it deposits its log files in 



