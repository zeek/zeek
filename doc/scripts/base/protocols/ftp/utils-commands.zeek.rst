:tocdepth: 3

base/protocols/ftp/utils-commands.zeek
======================================
.. zeek:namespace:: FTP


:Namespace: FTP

Summary
~~~~~~~
Runtime Options
###############
==================================================================== ===========================================================
:zeek:id:`FTP::cmd_reply_code`: :zeek:type:`set` :zeek:attr:`&redef` Possible response codes for a wide variety of FTP commands.
==================================================================== ===========================================================

Types
#####
================================================= ====================================================================
:zeek:type:`FTP::CmdArg`: :zeek:type:`record`     
:zeek:type:`FTP::PendingCmds`: :zeek:type:`table` Structure for tracking pending commands in the event that the client
                                                  sends a large number of commands before the server has a chance to
                                                  reply.
================================================= ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: FTP::cmd_reply_code
   :source-code: base/protocols/ftp/utils-commands.zeek 24 24

   :Type: :zeek:type:`set` [:zeek:type:`string`, :zeek:type:`count`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            ["ABOR", 226] ,
            ["REIN", 120] ,
            ["STOU", 553] ,
            ["MLSD", 150] ,
            ["RNTO", 503] ,
            ["CDUP", 530] ,
            ["CDUP", 501] ,
            ["APPE", 425] ,
            ["SYST", 530] ,
            ["PORT", 421] ,
            ["TYPE", 501] ,
            ["LIST", 125] ,
            ["RNTO", 530] ,
            ["PWD", 501] ,
            ["STOR", 125] ,
            ["CDUP", 200] ,
            ["MLSD", 250] ,
            ["SITE", 500] ,
            ["CWD", 550] ,
            ["CDUP", 550] ,
            ["QUIT", 500] ,
            ["MKD", 257] ,
            ["ALLO", 500] ,
            ["LIST", 425] ,
            ["CLNT", 200] ,
            ["<init>", 0] ,
            ["ABOR", 501] ,
            ["FEAT", 502] ,
            ["MLST", 150] ,
            ["APPE", 150] ,
            ["STOU", 550] ,
            ["USER", 332] ,
            ["PASV", 227] ,
            ["SYST", 421] ,
            ["STRU", 530] ,
            ["EPRT", 501] ,
            ["PASV", 530] ,
            ["USER", 530] ,
            ["APPE", 125] ,
            ["CDUP", 421] ,
            ["STOU", 451] ,
            ["HELP", 214] ,
            ["NLST", 426] ,
            ["RNFR", 450] ,
            ["LPRT", 521] ,
            ["ALLO", 530] ,
            ["STAT", 501] ,
            ["MACB", 550] ,
            ["PASS", 332] ,
            ["SITE", 502] ,
            ["SIZE", 550] ,
            ["LIST", 451] ,
            ["LIST", 426] ,
            ["APPE", 426] ,
            ["SMNT", 530] ,
            ["MLST", 250] ,
            ["TYPE", 530] ,
            ["HELP", 500] ,
            ["RNTO", 553] ,
            ["STOR", 530] ,
            ["NLST", 150] ,
            ["NLST", 451] ,
            ["SMNT", 501] ,
            ["ACCT", 230] ,
            ["MDTM", 550] ,
            ["APPE", 452] ,
            ["LIST", 450] ,
            ["NLST", 250] ,
            ["MDTM", 500] ,
            ["RETR", 450] ,
            ["NLST", 502] ,
            ["TYPE", 504] ,
            ["MLSD", 550] ,
            ["MODE", 421] ,
            ["OPTS", 451] ,
            ["RETR", 426] ,
            ["APPE", 530] ,
            ["STRU", 504] ,
            ["STAT", 502] ,
            ["RETR", 125] ,
            ["EPRT", 200] ,
            ["ALLO", 202] ,
            ["MKD", 502] ,
            ["STOU", 501] ,
            ["SYST", 502] ,
            ["REIN", 220] ,
            ["MLSD", 501] ,
            ["DELE", 530] ,
            ["USER", 421] ,
            ["NLST", 530] ,
            ["TYPE", 200] ,
            ["RMD", 250] ,
            ["DELE", 421] ,
            ["FEAT", 211] ,
            ["APPE", 500] ,
            ["RETR", 501] ,
            ["ABOR", 225] ,
            ["CWD", 250] ,
            ["STOU", 110] ,
            ["ALLO", 504] ,
            ["RNTO", 532] ,
            ["PWD", 500] ,
            ["STOR", 110] ,
            ["MODE", 502] ,
            ["PORT", 200] ,
            ["NLST", 125] ,
            ["RETR", 110] ,
            ["ACCT", 503] ,
            ["RMD", 502] ,
            ["REST", 200] ,
            ["RETR", 226] ,
            ["PASV", 500] ,
            ["STRU", 501] ,
            ["LIST", 502] ,
            ["STAT", 530] ,
            ["RETR", 500] ,
            ["PASS", 501] ,
            ["STOR", 553] ,
            ["APPE", 550] ,
            ["SMNT", 550] ,
            ["PASV", 501] ,
            ["SYST", 501] ,
            ["MKD", 550] ,
            ["PASV", 502] ,
            ["MODE", 530] ,
            ["STAT", 450] ,
            ["APPE", 226] ,
            ["MACB", 500] ,
            ["PASS", 230] ,
            ["STAT", 212] ,
            ["PASV", 421] ,
            ["STOU", 530] ,
            ["PASS", 530] ,
            ["SITE", 202] ,
            ["PASS", 500] ,
            ["APPE", 450] ,
            ["STOR", 450] ,
            ["LIST", 250] ,
            ["NLST", 500] ,
            ["PWD", 502] ,
            ["RNFR", 500] ,
            ["STOR", 501] ,
            ["DELE", 500] ,
            ["HELP", 421] ,
            ["NLST", 425] ,
            ["NLST", 550] ,
            ["STOR", 451] ,
            ["SYST", 215] ,
            ["RETR", 425] ,
            ["APPE", 532] ,
            ["LIST", 150] ,
            ["CWD", 500] ,
            ["USER", 331] ,
            ["OPTS", 501] ,
            ["PASS", 503] ,
            ["STOU", 532] ,
            ["STOU", 150] ,
            ["QUIT", 221] ,
            ["ACCT", 202] ,
            ["STOR", 425] ,
            ["MKD", 421] ,
            ["TYPE", 500] ,
            ["STOU", 125] ,
            ["SYST", 500] ,
            ["CDUP", 502] ,
            ["RETR", 451] ,
            ["RNFR", 502] ,
            ["TYPE", 421] ,
            ["STOR", 500] ,
            ["SIZE", 500] ,
            ["HELP", 211] ,
            ["RNTO", 250] ,
            ["REIN", 502] ,
            ["STRU", 200] ,
            ["RMD", 421] ,
            ["<init>", 421] ,
            ["STAT", 211] ,
            ["<init>", 120] ,
            ["LIST", 550] ,
            ["ABOR", 500] ,
            ["NOOP", 200] ,
            ["REIN", 421] ,
            ["STOR", 150] ,
            ["SMNT", 502] ,
            ["CDUP", 250] ,
            ["PORT", 501] ,
            ["MODE", 504] ,
            ["STAT", 421] ,
            ["MODE", 501] ,
            ["MDTM", 213] ,
            ["MKD", 501] ,
            ["LIST", 421] ,
            ["MLST", 226] ,
            ["STOR", 226] ,
            ["NOOP", 421] ,
            ["PWD", 421] ,
            ["FEAT", 500] ,
            ["APPE", 250] ,
            ["CLNT", 500] ,
            ["LIST", 501] ,
            ["STOU", 425] ,
            ["LIST", 530] ,
            ["SITE", 530] ,
            ["STOU", 250] ,
            ["RETR", 150] ,
            ["RNTO", 500] ,
            ["MLST", 501] ,
            ["REST", 501] ,
            ["MKD", 530] ,
            ["RNFR", 530] ,
            ["ALLO", 200] ,
            ["STRU", 500] ,
            ["MLSD", 500] ,
            ["STOU", 426] ,
            ["STAT", 213] ,
            ["RNFR", 421] ,
            ["ALLO", 501] ,
            ["RETR", 421] ,
            ["APPE", 421] ,
            ["USER", 501] ,
            ["QUIT", 0] ,
            ["USER", 230] ,
            ["RNFR", 350] ,
            ["STOU", 551] ,
            ["MODE", 500] ,
            ["STOR", 426] ,
            ["REST", 530] ,
            ["SMNT", 421] ,
            ["ABOR", 502] ,
            ["ACCT", 421] ,
            ["APPE", 502] ,
            ["SITE", 214] ,
            ["CWD", 421] ,
            ["NLST", 450] ,
            ["STOU", 226] ,
            ["EPRT", 522] ,
            ["REST", 500] ,
            ["RMD", 550] ,
            ["LPRT", 501] ,
            ["EPSV", 501] ,
            ["HELP", 501] ,
            ["DELE", 450] ,
            ["NLST", 501] ,
            ["EPSV", 500] ,
            ["APPE", 552] ,
            ["EPRT", 500] ,
            ["PWD", 257] ,
            ["MODE", 200] ,
            ["NLST", 226] ,
            ["RMD", 500] ,
            ["CWD", 530] ,
            ["APPE", 501] ,
            ["RMD", 530] ,
            ["STOR", 452] ,
            ["<missing>", 0] ,
            ["RETR", 530] ,
            ["NOOP", 500] ,
            ["REIN", 500] ,
            ["STOR", 532] ,
            ["ABOR", 421] ,
            ["APPE", 551] ,
            ["SMNT", 500] ,
            ["STOR", 550] ,
            ["RNFR", 501] ,
            ["USER", 500] ,
            ["ALLO", 421] ,
            ["ACCT", 500] ,
            ["RNTO", 502] ,
            ["MKD", 500] ,
            ["PASS", 421] ,
            ["STOU", 552] ,
            ["STOU", 452] ,
            ["CWD", 501] ,
            ["PORT", 500] ,
            ["MLST", 500] ,
            ["STOU", 450] ,
            ["STOU", 421] ,
            ["ACCT", 530] ,
            ["STRU", 421] ,
            ["STOU", 500] ,
            ["SIZE", 501] ,
            ["MDTM", 501] ,
            ["ACCT", 501] ,
            ["REST", 502] ,
            ["STOR", 421] ,
            ["RNTO", 421] ,
            ["RETR", 250] ,
            ["MLSD", 226] ,
            ["LIST", 500] ,
            ["DELE", 502] ,
            ["SMNT", 250] ,
            ["OPTS", 200] ,
            ["SITE", 501] ,
            ["APPE", 553] ,
            ["PASS", 202] ,
            ["SIZE", 213] ,
            ["STOR", 250] ,
            ["DELE", 250] ,
            ["STOR", 551] ,
            ["PWD", 550] ,
            ["STAT", 500] ,
            ["RMD", 501] ,
            ["RNTO", 501] ,
            ["HELP", 200] ,
            ["MACB", 200] ,
            ["DELE", 501] ,
            ["LPRT", 500] ,
            ["LIST", 226] ,
            ["REST", 350] ,
            ["CDUP", 500] ,
            ["APPE", 451] ,
            ["EPSV", 229] ,
            ["RETR", 550] ,
            ["DELE", 550] ,
            ["PORT", 530] ,
            ["CWD", 502] ,
            ["STOR", 552] ,
            ["NLST", 421] ,
            ["HELP", 502] ,
            ["SITE", 200] ,
            ["<init>", 220] ,
            ["SMNT", 202] ,
            ["RNFR", 550] ,
            ["MLST", 550] ,
            ["REST", 421] 
         }


   Possible response codes for a wide variety of FTP commands.

Types
#####
.. zeek:type:: FTP::CmdArg
   :source-code: base/protocols/ftp/utils-commands.zeek 4 16

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time`
         Time when the command was sent.

      cmd: :zeek:type:`string` :zeek:attr:`&default` = ``"<unknown>"`` :zeek:attr:`&optional`
         Command.

      arg: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Argument for the command if one was given.

      seq: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Counter to track how many commands have been executed.

      cwd_consumed: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Flag indicating if the arg of this CmdArg has been used
         to update cwd of c$ftp.


.. zeek:type:: FTP::PendingCmds
   :source-code: base/protocols/ftp/utils-commands.zeek 21 21

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`FTP::CmdArg`

   Structure for tracking pending commands in the event that the client
   sends a large number of commands before the server has a chance to
   reply.


