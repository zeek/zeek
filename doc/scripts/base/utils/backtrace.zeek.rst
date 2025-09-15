:tocdepth: 3

base/utils/backtrace.zeek
=========================



Summary
~~~~~~~
Functions
#########
================================================= ==================================
:zeek:id:`print_backtrace`: :zeek:type:`function` Prints a Zeek function call stack.
================================================= ==================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: print_backtrace
   :source-code: base/utils/backtrace.zeek 19 78

   :Type: :zeek:type:`function` (show_args: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`, one_line: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`, one_line_delim: :zeek:type:`string` :zeek:attr:`&default` = ``"|"`` :zeek:attr:`&optional`, skip: :zeek:type:`count` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`, to_file: :zeek:type:`file` :zeek:attr:`&default` = ``file "/dev/stdout" of string`` :zeek:attr:`&optional`) : :zeek:type:`void`

   Prints a Zeek function call stack.
   

   :param show_args: whether to print function argument names/types/values.
   

   :param one_line: whether to print the stack in a single line or multiple.
   

   :param one_line_delim: delimiter between stack elements if printing to one line.
   

   :param skip: the number of call stack elements to skip past, starting from zero,
         with that being the call to this function.
   

   :param to_file: the file to which the call stack will be printed.
   
   .. zeek:see:: backtrace


