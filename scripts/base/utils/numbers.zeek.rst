:tocdepth: 3

base/utils/numbers.zeek
=======================



Summary
~~~~~~~
Functions
#########
=============================================== =================================
:zeek:id:`extract_count`: :zeek:type:`function` Extract an integer from a string.
=============================================== =================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: extract_count

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, get_first: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`count`

   Extract an integer from a string.
   

   :s: The string to search for a number.
   

   :get_first: Provide `F` if you would like the last number found.
   

   :returns: The request integer from the given string or 0 if
            no integer was found.


