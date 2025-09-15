:tocdepth: 3

base/bif/plugins/Zeek_FTP.functions.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================= ==========================================================================
:zeek:id:`fmt_ftp_port`: :zeek:type:`function`    Formats an IP address and TCP port as an FTP PORT command.
:zeek:id:`parse_eftp_port`: :zeek:type:`function` Converts a string representation of the FTP EPRT command (see :rfc:`2428`)
                                                  to an :zeek:type:`ftp_port`.
:zeek:id:`parse_ftp_epsv`: :zeek:type:`function`  Converts the result of the FTP EPSV command (see :rfc:`2428`) to an
                                                  :zeek:type:`ftp_port`.
:zeek:id:`parse_ftp_pasv`: :zeek:type:`function`  Converts the result of the FTP PASV command to an :zeek:type:`ftp_port`.
:zeek:id:`parse_ftp_port`: :zeek:type:`function`  Converts a string representation of the FTP PORT command to an
                                                  :zeek:type:`ftp_port`.
================================================= ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: fmt_ftp_port
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 65 65

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, p: :zeek:type:`port`) : :zeek:type:`string`

   Formats an IP address and TCP port as an FTP PORT command. For example,
   ``10.0.0.1`` and ``1055/tcp`` yields ``"10,0,0,1,4,31"``.
   

   :param a: The IP address.
   

   :param p: The TCP port.
   

   :returns: The FTP PORT string.
   
   .. zeek:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv parse_ftp_epsv

.. zeek:id:: parse_eftp_port
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 30 30

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts a string representation of the FTP EPRT command (see :rfc:`2428`)
   to an :zeek:type:`ftp_port`.  The format is
   ``"EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :param s: The string of the FTP EPRT command, e.g., ``"|1|10.0.0.1|1055|"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_ftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port

.. zeek:id:: parse_ftp_epsv
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 52 52

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts the result of the FTP EPSV command (see :rfc:`2428`) to an
   :zeek:type:`ftp_port`.  The format is ``"<text> (<d><d><d><tcp-port><d>)"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :param str: The string containing the result of the FTP EPSV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv fmt_ftp_port

.. zeek:id:: parse_ftp_pasv
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 40 40

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts the result of the FTP PASV command to an :zeek:type:`ftp_port`.
   

   :param str: The string containing the result of the FTP PASV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_ftp_port parse_eftp_port parse_ftp_epsv fmt_ftp_port

.. zeek:id:: parse_ftp_port
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 17 17

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts a string representation of the FTP PORT command to an
   :zeek:type:`ftp_port`.
   

   :param s: The string of the FTP PORT command, e.g., ``"10,0,0,1,4,31"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_eftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port


