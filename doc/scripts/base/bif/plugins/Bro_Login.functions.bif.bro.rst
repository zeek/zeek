:tocdepth: 3

base/bif/plugins/Bro_Login.functions.bif.bro
============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
=============================================== ===================================================================
:bro:id:`get_login_state`: :bro:type:`function` Returns the state of the given login (Telnet or Rlogin) connection.
:bro:id:`set_login_state`: :bro:type:`function` Sets the login state of a connection with a login analyzer.
=============================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: get_login_state

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`) : :bro:type:`count`

   Returns the state of the given login (Telnet or Rlogin) connection.
   

   :cid: The connection ID.
   

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
   
   .. bro:see:: set_login_state

.. bro:id:: set_login_state

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, new_state: :bro:type:`count`) : :bro:type:`bool`

   Sets the login state of a connection with a login analyzer.
   

   :cid: The connection ID.
   

   :new_state: The new state of the login analyzer. See
              :bro:id:`get_login_state` for possible values.
   

   :returns: Returns false if *cid* is not an active connection
            or is not tagged as a login analyzer, and true otherwise.
   
   .. bro:see:: get_login_state


