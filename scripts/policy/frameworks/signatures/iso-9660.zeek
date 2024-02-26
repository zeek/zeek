##! Load signature for ISO 9660 disk image and increase
##! default_file_bof_buffer_size to make it functional.
@load-sigs ./iso-9660

# CD001 string is in the 17th sector.
@if ( default_file_bof_buffer_size < (16 + 1) * 2048 )
redef default_file_bof_buffer_size = (16 + 1) * 2048;
@endif
