:tocdepth: 3

base/utils/numbers.zeek
=======================



Summary
~~~~~~~
Functions
#########
============================================= =================================
:bro:id:`extract_count`: :bro:type:`function` Extract an integer from a string.
============================================= =================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: extract_count

   :Type: :bro:type:`function` (s: :bro:type:`string`, get_first: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`) : :bro:type:`count`

   Extract an integer from a string.
   

   :s: The string to search for a number.
   

   :get_first: Provide `F` if you would like the last number found.
   

   :returns: The request integer from the given string or 0 if
            no integer was found.


