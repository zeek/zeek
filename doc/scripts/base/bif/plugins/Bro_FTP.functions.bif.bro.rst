:tocdepth: 3

base/bif/plugins/Bro_FTP.functions.bif.bro
==========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
=============================================== ==========================================================================
:bro:id:`fmt_ftp_port`: :bro:type:`function`    Formats an IP address and TCP port as an FTP PORT command.
:bro:id:`parse_eftp_port`: :bro:type:`function` Converts a string representation of the FTP EPRT command (see :rfc:`2428`)
                                                to an :bro:type:`ftp_port`.
:bro:id:`parse_ftp_epsv`: :bro:type:`function`  Converts the result of the FTP EPSV command (see :rfc:`2428`) to an
                                                :bro:type:`ftp_port`.
:bro:id:`parse_ftp_pasv`: :bro:type:`function`  Converts the result of the FTP PASV command to an :bro:type:`ftp_port`.
:bro:id:`parse_ftp_port`: :bro:type:`function`  Converts a string representation of the FTP PORT command to an
                                                :bro:type:`ftp_port`.
=============================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: fmt_ftp_port

   :Type: :bro:type:`function` (a: :bro:type:`addr`, p: :bro:type:`port`) : :bro:type:`string`

   Formats an IP address and TCP port as an FTP PORT command. For example,
   ``10.0.0.1`` and ``1055/tcp`` yields ``"10,0,0,1,4,31"``.
   

   :a: The IP address.
   

   :p: The TCP port.
   

   :returns: The FTP PORT string.
   
   .. bro:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv parse_ftp_epsv

.. bro:id:: parse_eftp_port

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts a string representation of the FTP EPRT command (see :rfc:`2428`)
   to an :bro:type:`ftp_port`.  The format is
   ``"EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :s: The string of the FTP EPRT command, e.g., ``"|1|10.0.0.1|1055|"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_ftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port

.. bro:id:: parse_ftp_epsv

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts the result of the FTP EPSV command (see :rfc:`2428`) to an
   :bro:type:`ftp_port`.  The format is ``"<text> (<d><d><d><tcp-port><d>)"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :str: The string containing the result of the FTP EPSV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv fmt_ftp_port

.. bro:id:: parse_ftp_pasv

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts the result of the FTP PASV command to an :bro:type:`ftp_port`.
   

   :str: The string containing the result of the FTP PASV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_ftp_port parse_eftp_port parse_ftp_epsv fmt_ftp_port

.. bro:id:: parse_ftp_port

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts a string representation of the FTP PORT command to an
   :bro:type:`ftp_port`.
   

   :s: The string of the FTP PORT command, e.g., ``"10,0,0,1,4,31"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_eftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port


