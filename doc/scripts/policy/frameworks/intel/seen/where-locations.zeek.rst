:tocdepth: 3

policy/frameworks/intel/seen/where-locations.zeek
=================================================


:Imports: :doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ===============================================
:zeek:type:`Intel::Where`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`Conn::IN_ORIG`
                                             
                                             * :zeek:enum:`Conn::IN_RESP`
                                             
                                             * :zeek:enum:`DNS::IN_REQUEST`
                                             
                                             * :zeek:enum:`DNS::IN_RESPONSE`
                                             
                                             * :zeek:enum:`Files::IN_HASH`
                                             
                                             * :zeek:enum:`Files::IN_NAME`
                                             
                                             * :zeek:enum:`HTTP::IN_HOST_HEADER`
                                             
                                             * :zeek:enum:`HTTP::IN_REFERRER_HEADER`
                                             
                                             * :zeek:enum:`HTTP::IN_URL`
                                             
                                             * :zeek:enum:`HTTP::IN_USER_AGENT_HEADER`
                                             
                                             * :zeek:enum:`HTTP::IN_X_FORWARDED_FOR_HEADER`
                                             
                                             * :zeek:enum:`SMB::IN_FILE_NAME`
                                             
                                             * :zeek:enum:`SMTP::IN_CC`
                                             
                                             * :zeek:enum:`SMTP::IN_FROM`
                                             
                                             * :zeek:enum:`SMTP::IN_HEADER`
                                             
                                             * :zeek:enum:`SMTP::IN_MAIL_FROM`
                                             
                                             * :zeek:enum:`SMTP::IN_MESSAGE`
                                             
                                             * :zeek:enum:`SMTP::IN_RCPT_TO`
                                             
                                             * :zeek:enum:`SMTP::IN_RECEIVED_HEADER`
                                             
                                             * :zeek:enum:`SMTP::IN_REPLY_TO`
                                             
                                             * :zeek:enum:`SMTP::IN_TO`
                                             
                                             * :zeek:enum:`SMTP::IN_X_ORIGINATING_IP_HEADER`
                                             
                                             * :zeek:enum:`SSH::IN_SERVER_HOST_KEY`
                                             
                                             * :zeek:enum:`SSL::IN_SERVER_NAME`
                                             
                                             * :zeek:enum:`X509::IN_CERT`
============================================ ===============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

