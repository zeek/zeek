:tocdepth: 3

base/bif/plugins/Zeek_Login.functions.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================= ===================================================================
:zeek:id:`get_login_state`: :zeek:type:`function` Returns the state of the given login (Telnet or Rlogin) connection.
:zeek:id:`set_login_state`: :zeek:type:`function` Sets the login state of a connection with a login analyzer.
================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: get_login_state
   :source-code: base/bif/plugins/Zeek_Login.functions.bif.zeek 26 26

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`count`

   Returns the state of the given login (Telnet or Rlogin) connection.
   

   :param cid: The connection ID.
   

   :returns: False if the connection is not active or is not tagged as a
            login analyzer. Otherwise the function returns the state, which can
            be one of:
   
                - ``LOGIN_STATE_AUTHENTICATE``: The connection is in its
                  initial authentication dialog.
                - ``LOGIN_STATE_LOGGED_IN``: The analyzer believes the user has
                  successfully authenticated.
                - ``LOGIN_STATE_SKIP``: The analyzer has skipped any further
                  processing of the connection.
                - ``LOGIN_STATE_CONFUSED``: The analyzer has concluded that it
                  does not correctly know the state of the connection, and/or
                  the username associated with it.
   
   .. zeek:see:: set_login_state

.. zeek:id:: set_login_state
   :source-code: base/bif/plugins/Zeek_Login.functions.bif.zeek 40 40

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, new_state: :zeek:type:`count`) : :zeek:type:`bool`

   Sets the login state of a connection with a login analyzer.
   

   :param cid: The connection ID.
   

   :param new_state: The new state of the login analyzer. See
              :zeek:id:`get_login_state` for possible values.
   

   :returns: Returns false if *cid* is not an active connection
            or is not tagged as a login analyzer, and true otherwise.
   
   .. zeek:see:: get_login_state


