#!/usr/bin/perl -Tw

# s2b.pl

# Read and parse a Bro signature from a string or array reference
package Bro::Signature;
{
	use strict;
	require 5.006_001;
	require Exporter;
	use vars qw( $VERSION
				@ISA
				@EXPORT_OK
				$DEBUG );
	
	$VERSION = '1.10';
	@EXPORT_OK = qw( findkeyblocks );
	@ISA = qw( Exporter );
	$DEBUG = 0;
	
	sub new
	{
		my $sub_name = 'new';
		
		my $self;
		my $proto = shift;
		my $class = ref( $proto ) || $proto;
		my %args = @_;
		my $sig_data = {};
		
		if( defined( $args{string} ) )
		{
			if( !( $sig_data = parsesig( $args{string} ) ) )
			{
				return( undef );
			}
		}
		else
		{
			warn( "Signature must be passed in as a string for now.  Direct" .
				" object creation is not supported yet\n" );
			return( undef );
		}
		
		$self = $sig_data;
		bless( $self, $class );
		return( $self );
		
	}
	
	sub parsesig
	{
		my $sub_name = 'parsesig';
		
		my $sig_block = shift || return( undef );
		my $sig_data;
		my $ret_data = {};
		
		# Check on the storage of the data
		if( ref( $sig_block ) eq 'ARRAY' )
		{
			$sig_data = join( "\n", @{$sig_block} );
		}
		else
		{
			# Otherwise it gets treated as a string
			$sig_data = $sig_block;
		}
		
		my $parse_err = 0;
		
		if( $sig_data =~
			m/^signature[[:space:]]+([[:alnum:]_-]{3,})[[:space:]]*\{[[:space:]]*?\n?	# signature declaration
			(.+?)		# signature data
			[[:space:]]*\}$/xs )	# end of block
		{
			my $sig_id = $1;
			my $sig_options = $2;
			
			$ret_data->{sig_id} = $sig_id;
			
			my @raw_data;
			my $i = 0;
			
			foreach my $line( split( /\n/, $sig_options ) )
			{
				# Each line of the signature is stored in an
				 # array to maintain the order and any comments.
				 # The actual data is stored in a hash.
				 # Access of the data should be done through the methods
				 # to output the whole signature along with comments.
				
				# remove any leading spaces
				$line =~ s/^[[:space:]]*//;
				
				# Put the line into the raw_data array
				$raw_data[$i] = $line;
				
				# Strip any comments from the line
				$line =~ s/(?:[[:space:]]+|)#.+$//;
				
				my( $key, $value ) = split( /[[:space:]]+/, $line, 2 );
				# if there is still data in the line then process
				if( defined( $value ) )
				{
					# Remove any leading spaces
					$value =~ s/^[[:space:]]*//;
					# place a reference to the raw_data array for this attribute
					# set the value for this attribute instance
					push( @{$ret_data->{$key}}, { 
							'__raw_data_pos__' => $i,
							'__value__' => $value, },
					);
				}
				
				++$i;
			}
			
			$ret_data->{'__raw_data__'} = \@raw_data;
		}
		else
		{
			if( $DEBUG > 0 )
			{
				warn( "Signature read error. Could not find a valid signature block\n" );
			}
			$parse_err = 1;
		}
		
		if( $parse_err )
		{
			return( undef );
		}
		else
		{
			return( $ret_data );
		}
	}
	
	sub findkeyblocks
	{
		my $sub_name = 'findkeyblocks';
		
		my $string = shift;
		my $keyword = 'signature';
		my $key_len = length( $keyword );
		my @ret_blocks;
		my $block_idx = 0;			# Current idx of the keyword blocks that will be returned
		my $open_brace_count = 0;	# Number of open braces encountered
		my $close_brace_count = 0;	# number of close braces encountered
		my $len = length( $string );	# length of string passed in
		my $pos_idx = 0;			# current position of substring
		my $st_blk_pos = 0;			# string position of a new block
		my $ws = '';				# working string
		my $found_key_start = 0;		# flag that a new keyword block has started
		my $comment_line = 0;		# flag if comments are in effect
		my $quoted;			# flag if quoting is active. contents are the quote character
		
		# make sure the string is of non-zero length.  Add one more so our
		 # loop below works
		if( $len > 0 )
		{
			++$len;
		}
		else
		{
			return( undef );
		}
		
		# Push a space onto the front of the string.  This just helps in
		 # starting the pattern matching.  It's easier than writting a
		 # bunch more lines of code.
		$string = "\n" . $string;
		++$len;
		
		while( $pos_idx < $len )
		{
			# If the two numbers match then a complete block has been found.
			if( $open_brace_count == $close_brace_count and
				$open_brace_count > 0 )
			{
				$ret_blocks[$block_idx] = $ws;
				++$block_idx;
				$open_brace_count = 0;
				$close_brace_count = 0;
				$found_key_start = 0;
				$st_blk_pos = $pos_idx;
				$ws = '';
			}
			elsif( $close_brace_count > $open_brace_count )
			{
				# Looks like there was a syntax error perhaps the
				 # file contains a keyword but no valid block
				 # Reset the counters and backup to $st_blk_pos + 1
				if( $DEBUG > 0 )
				{
					warn( "Error in parsing $keyword, found closed brace",
						" for a block but no open brace at char position $pos_idx\n" );
				}
				$open_brace_count = 0;
				$close_brace_count = 0;
				$found_key_start = 0;
				$pos_idx = $st_blk_pos + 1;
				$st_blk_pos = '';
				$ws = '';
				next;
			}
			
			# Make sure that substr returns a value
			if( defined( my $wc = substr( $string, $pos_idx, 1 ) ) )
			{
				if( $quoted
					and $found_key_start )
				{
					if( $wc eq $quoted
						and substr( $string, $pos_idx - 1, 1 ) ne '\\' )
					{
						$quoted = undef;
					}
				}
				# check for comment '#' character which is active until the 
				 # start of a newline
				elsif( ! $comment_line and 
					$wc eq '#' and
					substr( $string, $pos_idx - 1, 1 ) ne '\\' )
				{
					$comment_line = 1;
				}
				# Check if the comment flag is set
				elsif( $comment_line )
				{
					# If the current character is a newline then reset the comment flag
					if( $wc =~ m/\n/ )
					{
						$comment_line = 0;
					}
				}
				# start this if not currently working in a block and not a comment
				elsif( ! $found_key_start and ! $comment_line )
				{
					# check if the keyword is found 
					if( $pos_idx + $key_len + 1 < $len
					and substr( $string, $pos_idx, $key_len ) eq $keyword )
					{
						# check to make sure that the keyword is followed by a space
						if( substr( $string, $pos_idx + $key_len, 1 ) =~
							m/[[:space:]]/ )
						{
							$found_key_start = 1;
							$st_blk_pos = $pos_idx;
						}
					}
				}
				elsif( $pos_idx + $key_len + 1 < $len
					and $found_key_start
					and substr( $string, $pos_idx, $key_len ) eq $keyword )
				{
					if( substr( $string, $pos_idx + $key_len, 1 ) =~
							m/[[:space:]]/ )
					{
						if( $DEBUG > 0 )
						{
							warn( "New $keyword keyword found inside of another $keyword block",
								" at char position $pos_idx\n" );
							
							#print "STRING => $string\n";
						}
						
						# Reset the search params
						$open_brace_count = 0;
						$close_brace_count = 0;
						$found_key_start = 0;
						++$pos_idx;
						$st_blk_pos = '';
						$ws = '';
						next;
					}
				}
				elsif( $wc eq '{' and 
					substr( $string, $pos_idx - 1, 1 ) ne '\\' )
				{
					++$open_brace_count;
				}
				elsif( $wc eq '}' and
					substr( $string, $pos_idx - 1, 1 ) ne '\\' )
				{
					++$close_brace_count;
				}
				elsif( ! $quoted
					and ! $comment_line
					and $found_key_start )
				{
					if( $wc eq '"'
						and substr( $string, $pos_idx - 1, 1 ) ne '\\' )
					{
						$quoted = $wc;
					}
				}
				else
				{
					
				}
				
				# Only append chars to the working string if in a $keyword block
				if( $found_key_start )
				{
					$ws = $ws . $wc;
				}
				++$pos_idx;
			}
			else
			{
				print "Failed to pull data out using substr at position $pos_idx\n";
				++$pos_idx;
			}
		}
		
		if( wantarray )
		{
			return( @ret_blocks );
		}
		else
		{
			return( \@ret_blocks );
		}
	}
	
	sub addcomment
	{
		my $sub_name = 'addcomment';
		
		my $self = shift || return( undef );
		my $comment = shift || return( undef );
		
		# Make sure the comment starts with a '#'
		if( $comment !~ m/^[[:space:]]*#/ )
		{
			$comment = '#' . $comment;
		}
		
		if( $self->{'__raw_data__'} )
		{
			my $next_idx = $#{$self->{'__raw_data__'}} + 1;
			$self->{'__raw_data__'}->[$next_idx] = $comment;
		}
		else
		{
			return( undef );
		}
		
		return( 1 );
	}
	
	sub addoption
	{
		my $sub_name = 'addoption';
		
		my $self = shift || return( undef );
		my $option = shift || return( undef );
		my $option_data = shift || return( undef );
		
		if( $self->{'__raw_data__'} )
		{
			my $next_idx = $#{$self->{'__raw_data__'}} + 1;
			$self->{'__raw_data__'}->[$next_idx] = $option . ' ' . $option_data;
			push( @{$self->{$option}}, 
				{ '__raw_data_pos__' => $next_idx,
				'__value__' => $option_data, } );
		}
		else
		{
			return( undef );
		}
		
		return( 1 );
	}
	
	sub deloption
	{
		my $sub_name = 'deloption';
		# Accepts at a minimum the object and an option to remove
		# For options that have multivalues the value can be passed in as 
		 # option_data to remove only the one value from the object.
		# If an option has multivalues and no option_data is given then all
		 # options are removed.
		
		
		my $self = shift || return( undef );
		my $match_option = shift || return( undef );
		my $match_data = shift;	#optional
		my $success = 0;
		my @raw_data_pos;
				
		if( defined( $match_data ) )
		{
			if( $DEBUG > 4 )
			{
				warn( "Method $sub_name has been asked to delete option '" .
					$match_option . "', value '" . $match_data . "'\n" );
			}
			# Must match on both the option key and it's value
			if( exists( $self->{$match_option} ) )
			{				
				if( ref( $self->{$match_option} ) eq 'ARRAY' )
				{
					if( $DEBUG > 4 )
					{
						warn( "Found a match on $match_option in signature\n" );
					}
					
					my $__found = 0;
					my @good_data;
					foreach my $opt_value( @{$self->{$match_option}} )
					{
						if( $opt_value->{'__value__'} eq $match_data )
						{
							++$__found;
							$success = 1;
							push( @raw_data_pos, $opt_value->{'__raw_data_pos__'} );
						}
						elsif( defined( my $tt = $opt_value->{'__value__'} ) )
						{
							push( @good_data, $opt_value );
						}
						
					}
					
					if( $success )
					{
						if( defined( $good_data[0] ) )
						{
							# Replace the object's old data with the good data
							$self->{$match_option} = [ @good_data ];
						}
						else
						{
							delete $self->{$match_option};
						}
					}
				}
			}
		}
		elsif( exists( $self->{$match_option} ) )
		{
			if( $DEBUG > 4 )
			{
				warn( "Method $sub_name has been asked to delete all data with" .
					" an option name of $match_option\n" );
			}
			
			foreach my $opt_data( @{$self->{$match_option}} )
			{
				push( @raw_data_pos, $opt_data->{'__raw_data_pos__'} );
			}
			delete $self->{$match_option};
			$success = 1;
		}
		
		
		if( $success )
		{
			# cleanup the __raw_data__ storage in the object
			# get the last index of the __raw_data__ array
			foreach my $idx( @raw_data_pos )
			{
				$self->{'__raw_data__'}->[$idx] = undef;
			}
			
			# Delete the 
		}
		
		return( $success );
		
	}
	
	sub output
	{
		my $sub_name = 'output';
		
		my $self = shift || return( undef );
		my %args = @_;
		my $ret_string;
		my $prefix = '';
		my $comments = 0;
		
		# Check on options
		if( $args{sigprefix} )
		{
			$prefix = $args{sigprefix};
		}
		
		if( defined( $args{comments} ) )
		{
			$comments = $args{comments};
		}
		else
		{
			$comments = 1;
		}
		
		# opening to a Bro signature block
		$ret_string = 'signature ' . $prefix . $self->{sig_id} . ' {' . "\n";
		
		if( $comments )
		{
			foreach my $line( @{$self->{'__raw_data__'}} )
			{
				if( defined( $line ) )
				{
					$ret_string = $ret_string . '  ' . $line . "\n";
				}
			}
		}
		else
		{
			while( my( $option, $opt_array ) = each( %{$self} ) )
			{
				if( $option ne '__raw_data__' and $option ne 'sig_id' )
				{
					foreach my $opt_data( @{$opt_array} )
					{
						$ret_string = $ret_string . 
						'  ' .
						$option .
						' ' .
						$opt_data->{'__value__'} .
						"\n";
					}
				}
			}
		}
		
		# closing of the Bro signature block
		$ret_string = $ret_string . '}';
		
		return( $ret_string );
	}
	
	sub option
	{
		my $sub_name = 'option';
		
		my $self = shift || return( undef );
		my $sig_option = shift || return( undef );
		my $ret_data;
		
		if( $self->{$sig_option} )
		{
			foreach my $data( @{$self->{$sig_option}} )
			{
				push( @{$ret_data}, $data->{'__value__'} );
			}
		}
		else
		{
			return( undef );
		}
		
		if( @{$ret_data} > 1 )
		{
			return( @{$ret_data} );
		}
		else
		{
			return( $ret_data->[0] );
		}
	}
	
	sub sigid
	{
		# This is the entire Bro signature id as parsed in from a 
		 # signature block
		my $sub_name = 'sigid';
		
		my $self = shift || return( undef );
		
		if( $self->{sig_id} )
		{
			return( $self->{sig_id} );
		}
		else
		{
			return( undef );
		}
	}
	
	sub openportlist
	{
		my $sub_name = 'openportlist';
		
		my $self = shift || return( undef );
		
	}
};


package Bro::S2b::Augment;
{
	use strict;
	require 5.006_001;
	use Config::General;
	#require Bro::Signature;
	
	use vars qw( $VERSION
			$DEBUG
			%VALID_AUGMENT_OPTIONS
			$QUOTE_PATT );
	
	$VERSION = '1.10';
	
	%VALID_AUGMENT_OPTIONS = (
		'active' =>
			{ fatal => '{1}',
			msg => "One required with values of T or F",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 0, },
		'comment' =>
			{ fatal => '*',
			msg => "Zero or more allowed, value is plain text",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 0, },
		'dst-ip' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'dst-port' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'src-ip' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'src-port' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'ip-proto' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'eval' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'ftp' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'header' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'http' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'http-request' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'http-request-header' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'http-reply-header' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'ip-options' =>
			{ fatal => '?',
			msg => "One or zero allowed. Not implemented yet.",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'payload' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommened.",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'payload-size' =>
			{ fatal => '?',
			msg => 'One or zero allowed.',
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'requires-signature' => 
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'requires-reverse-signature' =>
			{ fatal => '*',
			warn => '{0,10}',
			msg => "Zero or many with a max of 10 recommended",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'same-ip' =>
			{ fatal => '?',
			msg => 'One or zero allowed.',
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		'snort-rule-file' =>
			{ fatal => '?',
			msg => "Zero or one allowed, filename from where the Snort rule came from is recommened",
			no_modify => 1,
			write_to_cfg => 1,
			write_to_sig => 0, },
		'sid-rev' =>
			{ fatal => '{1}',
			msg => "One is required.  SID rev number provided in the Snort ruleset file",
			no_modify => 1,
			write_to_cfg => 0,
			write_to_sig => 0, },
		'sid' =>
			{ fatal => '{1}',
			msg => "One is required.  Sid number is provided in the Snort ruleset file",
			no_modify => 1,
			write_to_cfg => 0,
			write_to_sig => 0, },
		'sigaction' =>
			{ fatal => '{1}',
			msg => "One required with a Bro SigAction as a value",
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 0, },
		'tcp-state' =>
			{ fatal => '?',
			msg => 'One or zero allowed.',
			no_modify => 0,
			write_to_cfg => 1,
			write_to_sig => 1, },
		);
	
	$QUOTE_PATT = qr~(?:[=!]{2}|\;|[|]{2}|\"|\>|\<)~;
	
	sub new
	{
		my $sub_name = 'new';
		
		my $self;
		my $proto = shift;
		my $class = ref( $proto ) || $proto;
		my %args = @_;
		my $augment_objs = [];
		my $sig_data = {};
		
		if( defined( $args{filename} ) )
		{
			if( !( $augment_objs = getaugmentconfig( $args{filename} ) ) )
			{
				return( undef );
			}
			else
			{
				return( $augment_objs );
			}
		}
		else
		{
			if( validate( \%args ) )
			{
				$sig_data = \%args;
			}
			else
			{
				return( undef );
			}
		}
		
		$self = $sig_data;
		bless( $self, $class );
		return( $self );
		
	}
	
	sub getaugmentconfig
	{
		my $sub_name = 'getaugmentconfig';
		
		my $augment_file = shift || undef;
		my $valid_opts = \%VALID_AUGMENT_OPTIONS;
		my @ret_arr;
		my %aug_conf;
		my $conf;
		
		if( -r $augment_file )
		{
			$conf = Config::General->new( -ConfigFile => $augment_file,
							-LowerCaseNames => 1,
							-MergeDuplicateBlocks => 0,
							);
		}
		else
		{
			if( $DEBUG > 0 )
			{
				warn( "Error reading augment config at \"$augment_file\".\n" );
			}
			return( undef );
		}
		
		%aug_conf = $conf->getall();
		
		if( ref( $aug_conf{augment} ) eq 'HASH' )
		{
			%aug_conf = %{$aug_conf{augment}}
		}
		
		while( my( $sid_id, $aug_data ) = each( %aug_conf ) )
		{
			my( $sid_num, $sid_rev ) = split( /-/, $sid_id, 2 );
			my $invalid_sid = 0;
			
			# The sid_id is represents both the sid number and the rev
			 # in the form sid-rev, example: 540-2 would have a sid number
			 # of 540 and an rev of 2
			
			if( ref( $aug_data ) eq 'ARRAY' )
			{
				if( $DEBUG > 1 )
				{
					warn( "SID number $sid_num with rev number $sid_rev has duplicate" .
					" entries.  Keeping the first instance and removing all others\n" );
				}
				
				my $keep_data = $aug_conf{$sid_id}->[0];
				$aug_conf{$sid_id} = undef;
				$aug_conf{$sid_id} = $keep_data;
			}
			else
			{
				if( my $aug_obj = Bro::S2b::Augment->new( 'sid' => $sid_num,
										'sid-rev' => $sid_rev,
										%{$aug_data} ) )
				{
					push( @ret_arr, $aug_obj );
				}
				else
				{
					warn( "Failed to parse sid $sid_num, rev $sid_rev\n" );
					$invalid_sid = 1;
				}
			}
			
			if( $invalid_sid )
			{
				if( $DEBUG > 0 )
				{
					warn( "Snort SID number $sid_num is being ignored\n" );
				}
			}
		}
		
		if( $DEBUG > 4 )
		{
			warn( "\nMemory dump of augment config file $augment_file\n" );
			warn( $conf->save_string( \%aug_conf ) . "\n" );
			warn( "\n" );
		}
		
		if( wantarray )
		{
			return( @ret_arr );
		}
		else
		{
			return( \@ret_arr );
		}
	}
	
	sub validate
	{
		my $sub_name = 'validate';
		
		# The hash passed in is in the form
		 # <snort sid> => <hash ref of augment data>
		
		my $aug_data = shift || return( undef );
		my %ret_hash;
		my $invalid_sid = 0;
		my $sid_num = $aug_data->{sid};
		my $del_data = {};	# hash ref of options that will later be removed from a sig
		
		# make sure that the snort sid number is greater than 100
		if( $sid_num =~ m/^([[:digit:]]+)$/ and $sid_num > 100 )
		{
			$sid_num = $1;
		}
		
		# Check for a delete block
		if( exists( $aug_data->{delete} ) )
		{
			$del_data = $aug_data->{delete};
		}
		
		# Check to make sure that the sid contains only valid options.
		# Each option will be totalled as a string of 1's where each 1
		# represents one instance of a particular option.
		# Regular expression contained in %VALID_AUGMENT_OPTIONS for that
		# option will be evaluated against the quantity found.
		while( my( $sid_option, $sid_opt_data ) = each( %{$aug_data} ) )
		{
			my $option_count;
			if( defined( $VALID_AUGMENT_OPTIONS{$sid_option} ) )
			{
				# OK, all good
			}
			elsif( $sid_option eq 'delete' )
			{
				next;
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( "Option '$sid_option' in augment config" .
					" for SID number $sid_num is unknown." .
					"  Option will be ignored\n" );
				}
				
				delete $aug_data->{$sid_option};
				next;
			}
			
			if( ref( $sid_opt_data ) eq 'HASH' )
			{
				foreach( keys( %{$sid_opt_data} ) )
				{
					$option_count .= '1';
				}
			}
			elsif( ref( $sid_opt_data ) eq 'ARRAY' )
			{
				foreach( @{$sid_opt_data} )
				{
					$option_count .= '1';
				}
			}
			else
			{
				# Otherwise treat the sid_option as a scalar
				$option_count = 1;
			}
			
			my $fatal_exp = qr/1$VALID_AUGMENT_OPTIONS{$sid_option}->{fatal}/;
			if( $option_count =~ m/^$fatal_exp$/ )
			{
				# ok
				if( defined( $VALID_AUGMENT_OPTIONS{$sid_option}->{warn} ) )
				{
					my $warn_exp = qr/1$VALID_AUGMENT_OPTIONS{$sid_option}->{warn}/;
					if( $option_count =~ m/^$warn_exp$/ )
					{
						#ok
					}
					else
					{
						if( $DEBUG > 0 )
						{
							warn( "Warning for option '$sid_option' in SID number $sid_num, " .
							$VALID_AUGMENT_OPTIONS{$sid_option}->{msg} .
							"\n" );
						}
					}
				}
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( "Invalid SID option '$sid_option' in SID number $sid_num, " .
					$VALID_AUGMENT_OPTIONS{$sid_option}->{msg} .
					"\n" );
				}
				$invalid_sid = 1;
			}
		}
		
		
		while( my( $sid_option, $sid_opt_data ) = each( %{$del_data} ) )
		{
			if( defined( $VALID_AUGMENT_OPTIONS{$sid_option} ) )
			{
				# OK, all good
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( "Option '$sid_option' in the delete section of" .
					" augment config for SID number $sid_num is unknown." .
					"  Option will be ignored\n" );
				}
				
				delete $aug_data->{delete}->{$sid_option};
				next;
			}
		}
		
		if( $invalid_sid )
		{
			return( 0 );
		}
		else
		{
			return( 1 );
		}
	}
	
	sub augmentbrosig
	{
		my $sub_name = 'augmentbrosig';
		
		my $self = shift || return( undef );
		my $bro_sig_obj = shift || return( undef );
		my $new_bro_sig;
		my $err = 0;
		my $del_data = {};
		
		# Go through each option in the augment data
		while( my( $option, $opt_data ) = each( %{$self} )
			and !( $err ) )
		{
			# Is this the delete section of the data
			if( $option eq 'delete' and ref( $opt_data ) )
			{
				$del_data = $opt_data;
			}
			# check whether the option is allowed to be exported to 
			 # a Bro sig
			elsif( exists( $VALID_AUGMENT_OPTIONS{$option} )
				and $VALID_AUGMENT_OPTIONS{$option}->{write_to_sig} )
			{
				
				my @data_list;
				my $remove_before_add = 0;
				
				# Check if $opt_data has mutlivalues
				if( ref( $opt_data ) eq 'ARRAY' )
				{
					@data_list = @{$opt_data};
				}
				else
				{
					if( $VALID_AUGMENT_OPTIONS{$option}->{fatal} eq '?'
						or $VALID_AUGMENT_OPTIONS{$option}->{fatal} eq '{1}' )
					{
						$remove_before_add = 1;
					}
					@data_list = ( $opt_data );
				}
				
				foreach my $opt_value( @data_list )
				{
					if( $remove_before_add )
					{
						$bro_sig_obj->deloption( $option );
						
						if( $DEBUG > 2 )
						{
							warn( "Augment option $option for sigid " . $self->sigid()
								. " can only have one instance in a Bro siganture.\n" );
							warn( "Found a prexisting context for \"$option\" in the Bro signature"
								. " which will be replaced by the augment data.\n" );
						}
					}
					
					if( $bro_sig_obj->addoption( $option, $opt_value ) )
					{
						# ok
					}
					else
					{
						if( $DEBUG > 0 )
						{
							warn( "Failed to add augment option $option to Bro" .
								" signature object with sid of " .
								$bro_sig_obj->sigid . "\n" );
						}
						$err = 1;
						last;
					}
				}
			}
		}
		
		# Loop over the delete section of the data and remove matching
		 # data from a bro signature.
		while( my( $opt, $val ) = each( %{$del_data} ) and ! $err )
		{
			if( exists( $VALID_AUGMENT_OPTIONS{$opt} )
				and $VALID_AUGMENT_OPTIONS{$opt}->{write_to_sig} )
			{
				my @data_list;
				
				# Check if $opt_data has mutlivalues
				if( ref( $val ) eq 'ARRAY' )
				{
					@data_list = @{$val};
				}
				elsif( defined( $val ) )
				{
					$data_list[0] = $val;
				}
				else
				{
					next;
				}
				
				foreach my $opt_value( @data_list )
				{
					if( $bro_sig_obj->deloption( $opt, $opt_value ) )
					{
						# ok
					}
					else
					{
						if( $DEBUG > 0 )
						{
							warn( "Failed to remove augment option '$opt', value '$opt_value'" .
								" from Bro signature object with sid of " .
								$bro_sig_obj->sigid() . "\n" );
						}
						$err = 1;
						last;
					}
				}
			}
		}
		
		if( $err )
		{
			if( $DEBUG > 0 )
			{
				warn( "Unable to apply all options from augment object to the Bro signature\n" );
			}
			return( undef );
		}
		else
		{
			return( $bro_sig_obj );
		}
	}
	
	sub sid
	{
		my $sub_name = 'sid';
		
		my $self = shift || return( undef );
		
		if( my $sid = $self->{sid} )
		{
			return( $sid );
		}
		else
		{
			return( undef );
		}
	}
	
	sub rev
	{
		my $sub_name = 'rev';
		
		my $self = shift || return( undef );
		
		if( my $rev = $self->{'sid-rev'} )
		{
			return( $rev );
		}
		else
		{
			return( undef );
		}
	}
	sub sigid
	{
		my $sub_name = 'sigid';
		
		my $self = shift || return( undef );
		
		if( my $rev = $self->{'sid-rev'}
			and my $sid = $self->{sid} )
		{
			return( $sid . '-' . $rev );
		}
		else
		{
			return( undef );
		}
	}
	
	sub option
	{
		my $sub_name = 'option';
		
		my $self = shift || return( undef );
		my $aug_option = shift || return( undef );
		my $ret_data;
		
		if( $self->{$aug_option} )
		{
			if( ( $self->{$aug_option} ) eq 'ARRAY' )
			{
				foreach my $data( @{$self->{$aug_option}} )
				{
					push( @{$ret_data}, $data );
				}
			}
			else
			{
				push( @{$ret_data}, $self->{$aug_option} );
			}
		}
		else
		{
			return( undef );
		}
		
		if( @{$ret_data} > 1 )
		{
			return( @{$ret_data} );
		}
		else
		{
			return( $ret_data->[0] );
		}
	}
	
	sub active
	{
		my $sub_name = 'active';
		
		my $self = shift || return( undef );
		my $new_status = shift;
		my $ret_status = 0;
		
		# NOTE, for now the active status is kept as a character value.
		 # This just makes it easy for importing augment data into objects
		 # This needs to be changed internally but for now the user doesn't
		 # know the difference.
		
		if( defined( $new_status ) )
		{
			if( $new_status =~ m/^(?:t|1)/i )
			{
				$self->{active} = 'T';
			}
			else
			{
				$self->{active} = 'F';
			}
		}
		
		if( ! exists( $self->{active} ) )
		{
			$ret_status = undef;
		}
		elsif( $self->{active} =~ m/^t/i )
		{
			$ret_status = 1;
		}
		
		return( $ret_status );
	}
	
	sub output
	{
		my $sub_name = 'output';
		
		my $self = shift || return( undef );
		my $ret_string = '';
		my $sid_num;
		my $sid_rev;
		
		if( $sid_num = $self->sid() and $sid_rev = $self->rev() )
		{
			# ok
		}
		else
		{
			return( undef );
		}
		
		my $already_quoted = qr/^\".+\"$/;
		foreach my $key( sort( keys( %{$self} ) ) )
		{
			my $value = $self->{$key};
			if( $VALID_AUGMENT_OPTIONS{$key}->{write_to_cfg} )
			{
				# If the option data has muti values
				if( ref( $value ) )
				{
					foreach my $value_inst( @{$value} )
					{
						if( $value_inst =~ $QUOTE_PATT
							and $value_inst !~ $already_quoted )
						{
							$value_inst = '"' . $value_inst . '"';
						}
						$ret_string = $ret_string . '  ' . $key . ' ' . $value_inst ."\n";
					}
				}
				# Otherwise the option value is reated as a scalar
				else
				{
					if( $value =~ $QUOTE_PATT
						and $value !~ $already_quoted )
					{
						$value = '"' . $value . '"';
					}
					$ret_string = $ret_string . '  ' . $key . ' ' . $value . "\n";
				}
			}
		}
		
		if( length( $ret_string ) > 3 )
		{
			# prepend the beginning of the augment block
			$ret_string = "<augment $sid_num-$sid_rev>\n" . $ret_string;
			
			# append the closing of the augment block
			$ret_string = $ret_string . '</augment>';
			
			return( $ret_string );
		}
		else
		{
			return( undef );
		}
	}
	
	sub merge
	{
		my $sub_name = 'merge';
		# will attempt to merge an augment object together with either a
		 # valid data strcuture or another augment object.  There is 
		 # no checking on whether the objects are similar in any way
		 # only that the data from the source does not cause the target
		 # to become invalid according to %VALID_AUGMENT_OPTIONS.
		# If an attempt to add a value exceeds the allowable quantity for 
		 # a given option then the option from the source object will replace
		 # the target object's option.  Otherwise the option will just be added
		 # If a delete block exists then the option that matches will be
		 # deleted from the target.  A final check will be made after all 
		 # data has been processed to make sure that the target still conforms 
		 # to the requirements in %VALID_AUGMENT_OPTIONS.
		
		my $self = shift || return( undef );	# Merge to, target
		my $new_data = shift || return( undef );	# Merge from, source
		# Make a copy of the object.  The copy will be operated on and once
		 # all tests have completed it will replace the contents of the 
		 # original object.
		my $wo = Bro::S2b::Augment->new( %{$self} );	# Working Object
		my $del_opts = {};
		my $failed = 0;
		
		while( my( $key, $value ) = each( %{$new_data} ) )
		{
			if( $key eq 'delete' )
			{
				$del_opts = $value;
			}
			else
			{
				if( ! $wo->add( $key, $value ) )
				{
					# Failed to add in the value
					if( $DEBUG > 0 )
					{
						$failed = 1;
						warn( "Failed to add option $key to augment object\n" );
					}
				}
			}
		}
		
		while( my( $del_opt, $del_val ) = each( %{$del_opts} ) )
		{
			if( ! $wo->del( $del_opt, $del_val ) )
			{
				if( $DEBUG > 0 )
				{
					$failed = 1;
					warn( "Failed to delete option $del_opt from object\n" );
				}
			}
		}
		
		if( ! validate( $wo ) )
		{
			if( $DEBUG > 0 )
			{
				warn( "There was an error in validating the merged augment object." .
				"  No changes made to the original augment object.\n" );
			}
			return( undef );
		}
		
		if( ! $failed )
		{
			return( $wo );
		}
		else
		{
			if( $DEBUG > 0 )
			{
				warn( "One or more operations failed during an augment merge." .
				"  Original object has not been modified\n" );
			}
			return( undef );
		}
	}
	
	sub add
	{
		my $sub_name = 'add';
		
		my $self = shift || return( undef );
		my $opt = shift || return( undef );
		my $val = shift;
		my $cur_contents;
		my $opt_quan = '';
		my $eval_quan = $VALID_AUGMENT_OPTIONS{$opt}->{fatal};
		
		if( ! $VALID_AUGMENT_OPTIONS{$opt} )
		{
			if( $DEBUG > 0 )
			{
				warn( "Attempt to merge an unknown option \"$opt\" into an augment object\n" );
			}
			return( undef );
		}
		
		if( $VALID_AUGMENT_OPTIONS{$opt}->{no_modify} )
		{
			if( $DEBUG > 0 )
			{
				warn( "Failed to add option $opt.  Modification is forbidden by configuration\n" );
			}
			return( undef );
		}
		
		# figure out what type of value is stored
		if( exists( $self->{$opt} ) and ref( $self->{$opt} ) eq 'ARRAY' )
		{
			my @t1 = @{$self->{$opt}};
			$cur_contents = \@t1;
			foreach( @{$cur_contents} )
			{
				$opt_quan .= '1';
			}
		}
		else
		{
			$cur_contents = $self->{$opt};
			$opt_quan = '1';
		}
		
		# figure out if we should replace or add
		# If the allowed option count is a max of one and we have only one option
		 # to add then this is an overwrite
		if( $eval_quan eq'?' or $eval_quan eq '{1}' )
		{
			if( $opt_quan =~ m/^1|$/ )
			{
				$self->{$opt} = $val;
				if( $DEBUG > 2 )
				{
					warn( "Added/replaced option $opt with contents $val\n" );
				}
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( "Tried to add more values to an option than the option type allows.\n" );
				}
				return( undef );
			}
		}
		else
		{
			$opt_quan .= '1';
			if( $opt_quan =~ m/^1$eval_quan$/ )
			{
				# Check if the data structure is an array, if not change it
				if( ! exists( $self->{$opt} ) )
				{
					$self->{$opt} = [];
				}
				elsif( ref( $self->{$opt} ) ne 'ARRAY' )
				{
					my $cur_val = $self->{$opt};
					delete( $self->{$opt} );
					$self->{$opt}->[0] = $cur_val;
				}
				
				push( @{$self->{$opt}}, $val );
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( $VALID_AUGMENT_OPTIONS{$opt}->{msg} . "\n" );
				}
				return( undef );
			}
		}
		
		# Search the delete section of the data and remove any matching entries
		if( ref( $self->{delete} ) )
		{
			# Need to complete later!
		}
		
		return( $self );
	}
	
	sub del
	{
		my $sub_name = 'del';
		
		my $self = shift || return( undef );
		my $opt = shift || return( undef );
		my $opt_val = shift || '';
		my $opt_quan = '';
		my $eval_quan = $VALID_AUGMENT_OPTIONS{$opt}->{fatal};
		
		if( ! $VALID_AUGMENT_OPTIONS{$opt} )
		{
			if( $DEBUG > 0 )
			{
				warn( "Attempt to remove an unknown option \"$opt\" from an augment object\n" );
			}
			return( undef );
		}
		
		if( $VALID_AUGMENT_OPTIONS{$opt}->{no_modify} )
		{
			if( $DEBUG > 0 )
			{
				warn( "Failed to delete option $opt.  Modification is forbidden by configuration\n" );
			}
			return( undef );
		}
		
		if( ! exists( $self->{$opt} ) )
		{
			# no option with the name in $opt exists
			return( 0 );
		}
		elsif( ref( $self->{$opt} ) eq 'ARRAY' )
		{
			my @t1 = @{$self->{$opt}};
			my $cur_contents = \@t1;
			my $found = 0;
			my @new_contents;
			
			foreach my $cont_inst( @{$cur_contents} )
			{
				if( $cont_inst eq $opt_val )
				{
					++$found;
				}
				else
				{
					$opt_quan .= '1';
					push( @new_contents, $cont_inst );
				}
			}
			
			if( $found )
			{
				if( $opt_quan =~ /^1$eval_quan$/ )
				{
					delete( $self->{$opt} );
					$self->{$opt} = \@new_contents;
				}
				else
				{
					if( $DEBUG > 0 )
					{
						warn( "Removal of option $opt failed." . $VALID_AUGMENT_OPTIONS{$opt}->{msg} . "\n" );
					}
					return( undef );
				}
			}
			else
			{
				if( $DEBUG > 2 )
				{
					warn( "Could not find '$opt' with value '$opt_val' to delete.  No big deal\n" );
				}
			}
		}
		else
		{
			$opt_quan = '';
			
			if( $self->{$opt} eq $opt_val )
			{
				if( $opt_quan =~ /^1$eval_quan$/ )
				{
					delete( $self->{$opt} );
				}
				else
				{
					if( $DEBUG > 0 ) 
					{
						warn( "Removal of option $opt is not allowed," . $VALID_AUGMENT_OPTIONS{$opt}->{msg} . "\n" );
					}
					return( undef );
				}
			}
			else
			{
				if( $DEBUG > 2 )
				{
					warn( "Could not find '$opt' with value '$opt_val' to delete.  No big deal\n" );
				}
			}
		}
		
		return( $self );
	}
};


#####################################################################
##### s2b.pl	Snort to Bro rule conversion script
##### Roger Winslow
#####
#####################################################################


use strict;
require 5.006_001;	# 5.6.1 minimum is required.
use Config::General;
use Getopt::Long;
Getopt::Long::Configure qw( no_ignore_case no_getopt_compat );

# clear these shell environment variables so Taint mode doesn't complain
$ENV{PATH} = '';
$ENV{BASH_ENV} = '';
$ENV{ENV} = '';

use vars qw( $VERSION
			%DEFAULT_CONFIG
			$SNORT_TO_BRO_PROG
			$DEBUG );

$VERSION = '1.10';
$DEBUG = 1;
%DEFAULT_CONFIG = ( configdir => '/usr/local/etc/bro/s2b',
				mainconfig => 's2b.cfg',
				augmentconfig => 's2b-augment.cfg',
				useraugmentconfig => 's2b-user-augment.cfg',
				sigactiondest => 's2b-sigaction.bro',
				brosignaturedest => 's2b.sig',
				sigmapconfig => 's2b-sigmap.cfg',
				defaultsigaction => 'SIG_LOG',
				rulesetaugmentconfig => 's2b-ruleset-augment.cfg',
				sigprefix => 's2b-',
				snortrulesetdir => './',
				ignorehostdirection => 1,
				);

# This is hardcoded until I get to intergrating the Snort conversion into 
 # a PERL program.
$SNORT_TO_BRO_PROG = './snort2bro';

# Until I can rewrite the python conversion script it will be used for initial conversion
 # make sure it runs before continuing on.
if( my $result = `$SNORT_TO_BRO_PROG --help 2>&1` )
{
	# ok.
}
else
{
	warn( "Unable to run $SNORT_TO_BRO_PROG.  Check to make sure that the python run" .
	" path is set correctly in the program.\n" );
	exit( 1 );
}

# ref to hash containing all config data
my $config = {};
$config = getconfig( \%DEFAULT_CONFIG );

# Build the ruleset exclusion list
my $ignorerules = {};
$ignorerules = getignorerules( $config );

# Parse and store the system level augment file
# An array ref containing Bro::S2b::Augment objects will be returned in 
 # $augment_objects
my $augment_objects = [];
if( $augment_objects = Bro::S2b::Augment->new( filename => $config->{augmentconfig} ) )
{
	# ok
}
else
{
	if( $DEBUG > 0 )
	{
		warn( "Unable to retrieve any augment data." . 
			"  This can be expected if the file has not been created yet.\n" );
		if( ! $config->{updateaugment} )
		{
			warn( "Perhaps you have forgotten to run --updateaugment first?\n" );
		}
	}
}

my $snort_rule_files = [];
$snort_rule_files = getsnortrulefiles( $config->{snortrulesetdir}, $ignorerules );

# Is this a request to update the s2b-augment.cfg file?
if( $config->{updateaugment} )
{
	my $ruleset_based_augment;
	my $new_augment_data;
	my $sigmap = {};
	my %existing_sidrev;
	
	# Read and parse the Snort alert classtype to Bro SigAction mappings
	$sigmap = getsigmap( $config->{sigmapconfig} );
	
	# Build a hash of "sid-rev" strings from the existing augment objects
	 # (if any)
	foreach my $aug_obj( @{$augment_objects} )
	{
		my $key = $aug_obj->sigid();
		$existing_sidrev{$key} = 1;
	}
	
	# Read and parse the ruleset augment data which is to be included into 
	 # the augment config based on the Snort ruleset from which they come.
	if( $config->{rulesetaugmentconfig} )
	{
		$ruleset_based_augment = getrulesetaugment( $config->{rulesetaugmentconfig} );
	}
	
	# Build the augment file
	$new_augment_data = buildaugment( $snort_rule_files, $sigmap ) || [];
	
	my @append_aug_list;
	# Check for new augment objects
	foreach my $new_aug( @{$new_augment_data} )
	{
		if( ! $existing_sidrev{$new_aug->sigid()} )
		{
			$new_aug->option( 'snort-rule-file' ) =~ m/([^\/]+)$/;
			my $aug_snort_rulename = $1;
			if( exists( $ruleset_based_augment->{$aug_snort_rulename} )  )
			{
				if( !(  $new_aug = $new_aug->merge( $ruleset_based_augment->{$aug_snort_rulename} ) ) )
				{
					next;
				}
			}
			
			push( @append_aug_list, $new_aug );
		}
	}
	
	if( @append_aug_list > 0 )
	{
		appendaugment( \@append_aug_list, $config->{augmentconfig} );
	}
	
	if( $DEBUG > 0 )
	{
		my $num_aug_blocks = scalar( @append_aug_list );
		if( $num_aug_blocks > 0 )
		{
			warn( "Added a total of $num_aug_blocks new augment data blocks to augment file " . $config->{augmentconfig} . "\n" );
		}
		else
		{
			warn( "No new augment data found.  Nothing added to augment file " . $config->{augmentconfig} . "\n" );
		}
	}
}
# Else assume this is a request to build Bro signatures
else
{
	my %sigaction_list;
	my @active_sigs;
	
	# Parse and store the user level augment file
	# An array ref containing Bro::S2b::Augment objects will be returned in 
	 # $user_augment_objects
	my $user_augment_objects = [];
	if( -r $config->{useraugmentconfig} and
		$user_augment_objects = Bro::S2b::Augment->new( filename => $config->{useraugmentconfig} ) )
	{
		# ok
	}
	else
	{
		if( $DEBUG > 1 )
		{
			warn( "Unable to retrieve any user level augment data." . 
				"  This is non-fatal and can be expected if the file has not been created yet.\n" );
		}
	}
	
	# Loop over each user augment object and build an index of sigids
	my %user_aug_obj_idx;
	for( my $i=0; $i < scalar( @{$user_augment_objects} ); ++$i )
	{
		$user_aug_obj_idx{$user_augment_objects->[$i]->sigid()} = $i;
	}
	
	my $ignore_snort_sids = {};
	$ignore_snort_sids = getignoresids( $augment_objects );

	# An array ref containing Bro::Signature objects will be returned in
	 # $converted_snort_rules
	my $converted_snort_rules = {};
	$converted_snort_rules = convertfromsnort( $snort_rule_files,
						$ignore_snort_sids );
	
	# Loop over the list of Bro::Signature objects and process each
	foreach my $sig_obj( @{$converted_snort_rules} )
	{
		my $sig_is_active = 0;
		my $user_aug_obj;
		my $sig_obj_id = $sig_obj->sigid();
		my $augment_obj;
		# Find the corresponding Bro::S2b::Augment object.  The match is found
		 # by comparing each object's sigid (minus the prefix if any).
		# I realize at this point that this is a bit of a waste.  I'll work on a
		 # better indexed version later.
		foreach my $augment_obj( @{$augment_objects} )
		{
			# Compare the sigids and see if they match
			if( $augment_obj->sigid() eq $sig_obj_id )
			{
				# Look for a matching user augment option and put it in
				 # $user_aug_obj if found.
				if( exists( $user_aug_obj_idx{$sig_obj_id} ) )
				{
					$user_aug_obj = $user_augment_objects->[$user_aug_obj_idx{$sig_obj_id}];
				}
				
				# Determine if the rule is active
				if( $augment_obj->active() )
				{
					$sig_is_active = 1;
				}
				if( $user_aug_obj and defined( $user_aug_obj->active() ) )
				{
					$sig_is_active = $user_aug_obj->active();
				}
				
				# Skip this instance if the sig is not set to active
				if( ! $sig_is_active )
				{
					# must be inactive. No need to continue processing this 
					 # signature
					last;
				}
				
				# Check whether the connection direction information should be 
				 # ignored.  If so then remove it from the Bro::Signature object.
				if( $config->{ignorehostdirection} )
				{
					if( my $dst_ip = $sig_obj->option( 'dst-ip' ) )
					{
						if( $dst_ip =~ m/[[:alpha:]]+/ )
						{
							$sig_obj->deloption( 'dst-ip' );
						}
					}
					
					if( my $src_ip = $sig_obj->option( 'src-ip' ) )
					{
						if( $src_ip =~ m/[[:alpha:]]+/ )
						{
							$sig_obj->deloption( 'src-ip' );
						}
					}
				}

				# Modify the Bro::Signature object and include the augment data.
				if( $augment_obj->augmentbrosig( $sig_obj ) )
				{
					# If user augment data exists then apply it now
					if( $user_aug_obj )
					{
						$user_aug_obj->augmentbrosig( $sig_obj );
					}
					
					# Determine which sigaction to use, system or user
					my $cur_sigaction;
					if( $user_aug_obj and $user_aug_obj->option( 'sigaction' ) )
					{
						$cur_sigaction = $user_aug_obj->option( 'sigaction' );
					}
					else
					{
						$cur_sigaction = $augment_obj->option( 'sigaction' );
					}
					
					# Check if the sigaction is anything other than the default
					# If so then add it to the hash.
					if( $cur_sigaction ne $config->{defaultsigaction} )
					{
						$sigaction_list{$sig_obj_id} = $cur_sigaction;
					}
					
					# Put the bro signature object into the active list of
					 # signatures
					push( @active_sigs, $sig_obj );
				}
				else
				{
					if( $DEBUG > 0 )
					{
						warn( "Failed to augment Bro signature $sig_obj_id\n" );
					}
				}

				last;
			}
		}
	}
		
	# Write the sigactions to a file or if the file in $config is an empty string 
	 # then send it to STDOUT
	if( $config->{sigactiondest} )
	{
		if( open( OUTFILE, '>', $config->{sigactiondest} ) )
		{
			outputsigactions( \%sigaction_list, \*OUTFILE );
		}
		else
		{
			warn( "Failed to open file " . $config->{sigactiondest} . " for writing, unable to continue\n" );
			exit( 1 );
		}
		
		close( OUTFILE );
	}
	else
	{
		outputsigactions( \%sigaction_list );
	}
	
	
	# Output the final signatures or if the file in $config is an empty string 
	 # then send it to STDOUT
	if( $config->{brosignaturedest} )
	{
		if( open( OUTFILE, '>', $config->{brosignaturedest} ) )
		{
			outputsigs( \@active_sigs, \*OUTFILE );
		}
		else
		{
			warn( "Failed to open file " . $config->{brosignaturedest} . " for writing, unable to continue\n" );
			exit( 1 );
		}
		
		close( OUTFILE );
	}
	else
	{
		outputsigs( $converted_snort_rules );
	}
	
}


exit( 0 );



#################################################
#####
#####  Begin subroutines
#####
#################################################

sub getconfig
{
	my $sub_name = 'getconfig';
	
	my $arg1 = shift || \%DEFAULT_CONFIG;
	my %default_config;
	my %cmd_line_cfg;
	my $main_config_file;
	my %config;
	
	if( ref( $arg1 ) eq 'HASH' )
	{
		%default_config = %{$arg1};
	}
	else
	{
		return( undef );
	}
	
	GetOptions( \%cmd_line_cfg,
			'configdir=s',
			'mainconfig=s',
			'augmentconfig=s',
			'useraugmentconfig=s',
			'sigactiondest=s',
			'brosignaturedest=s',
			'sigmapconfig=s',
			'snortrulesetdir=s',
			'defaultsigaction=s',
			'ignorehostdirection:s',
			'rulesetaugmentconfig',
			'updateaugment',
			'usage|help|h',
			'debug|verbose|d|v:i',
			'version|V',
			'copyright', );
	
	# Check for options which will prevent the program from running
	# any further
	if( $cmd_line_cfg{usage} )
	{
		print usage();
		exit( 0 );
	}
	elsif( $cmd_line_cfg{version} )
	{
		print version();
		exit( 0 );
	}
	elsif( $cmd_line_cfg{copyright} )
	{
		print copyright();
		exit( 0 );
	}
	else
	{
		# just continue on
	}
	
	if( ! $cmd_line_cfg{mainconfig} )
	{
		if( defined( $ARGV[0] ) )
		{
			$cmd_line_cfg{mainconfig} = $ARGV[0];
		}
		else
		{
			$cmd_line_cfg{mainconfig} = $default_config{mainconfig};
		}
	}
	
	$main_config_file = $cmd_line_cfg{mainconfig};

	my $conf = Config::General->new( -ConfigFile => $main_config_file,
						-LowerCaseNames => 1,
						);
	
	%config = $conf->getall;
	$config{'mainconfig'} = $main_config_file;
	
	# Any args passed through the command line will override file options
	while( my( $key, $value ) = each( %cmd_line_cfg ) )
	{
		$config{$key} = $value;
	}
	
	# Set default values for options that have not already been configured
	while( my( $key, $value ) = each( %{$arg1} ) )
	{
		if( ! exists( $config{$key} ) )
		{
			$config{$key} = $value;
		}
	}
	
	# Set Debug level
	$DEBUG = $config{debug} if exists( $config{debug} );
		
	if( checkconfig( \%config ) )
	{
		if( $DEBUG > 4 )
		{
			warn( "Configuration memory dump:\n" );
			warn( $conf->save_string( \%config ) );
			warn( "\n" );
		}
			return( \%config );
	}
	else
	{
		warn( "exiting program" );
		exit( 1 );
	}
}

sub checkconfig
{
	my $sub_name = 'checkconfig';
	
	my $cfg_hash = shift || return undef;
	
	# Check to make sure that the config directory is defined.
	if( defined( $cfg_hash->{'configdir'} ) )
	{
		# Check to make sure that the config directory has a sane value.
		if( $cfg_hash->{configdir} !~ m/[*;`{}%]+/ and
				$cfg_hash->{configdir} =~ m~^([[:print:]]{1,1024}?)/*$~ )
		{
			$cfg_hash->{configdir} = $1;
			if( !( -d $cfg_hash->{configdir} ) )
			{
				warn( "configdir '" .$cfg_hash->{configdir} . "' is not a directory\n" );
				return( 0 );
			}
		}
		else
		{
			warn( "Config directory contains invalid characters or is longer than 1024 bytes\n" );
			return( 0 );
		}
	}
	else
	{
		warn( "No config directory specified\n" );
		return( 0 );
	}
	
	# Check to make sure that the Snort rule directory is
	# specified and readable
	if( defined( $cfg_hash->{snortrulesetdir} ) )
	{
		if( -d $cfg_hash->{snortrulesetdir} )
		{
			if( ! -r $cfg_hash->{snortrulesetdir} )
			{
				warn( "Unable to read directory " . $cfg_hash->{snortrulesetdir} ."\n" );
				return( 0 );
			}
			else
			{
				# Strip of any trailing slash on the end
				$cfg_hash->{snortrulesetdir} =~ m~^([[:print:]]+?)/*$~;
				$cfg_hash->{snortrulesetdir} = $1;
			}
		}
		else
		{
			warn( $cfg_hash->{snortrulesetdir} . " is not a valid directory\n" );
			return( 0 );
		}
	}
	else
	{
		warn( "No snortruleset directory has been specified\n" );
		return( 0 );
	}
	
	# Check to make sure the sidprefix only conatins alphanumeric and dash characters
	if( defined( $cfg_hash->{sidprefix} ) )
	{
		if( $cfg_hash->{sidprefix} =~ m/^([[:alnum:]-]*)$/ )
		{
			$cfg_hash->{sidprefix} = $1;
		}
		else
		{
			warn( "Invalid charcters in the sidprefix.  May only contain alphanumeric and dash characters\n" );
			return( 0 );
		}
	}
	else
	{
		# else set it to a blank string
		$cfg_hash->{sidprefix} = '';
	}
	
	# Check to make sure default-sigaction is valid and set otherwise use 
	 # the default. Need to tie into the Bro config later to thoroughly check this.
	if( defined( $cfg_hash->{defaultsigaction} ) )
	{
		if( $cfg_hash->{defaultsigaction} =~ m/^[[:alnum:]_]+$/ )
		{
			# ok
		}
		else
		{
			warn( "Default Bro SigAction --default-sigaction has invalid characters\n" );
		}
	}
	else
	{
		warn( "No default Bro SigAction --default-sigaction has been set\n" );
		return( undef );
	}
	
	# Check the ignorehostdirection option for values other than true or false
	if( defined( $cfg_hash->{ignorehostdirection} ) )
	{
		if( $cfg_hash->{ignorehostdirection} =~ m/^(?:f|0)/i )
		{
			$cfg_hash->{ignorehostdirection} = 0;
		}
		elsif( $cfg_hash->{ignorehostdirection} )
		{
			$cfg_hash->{ignorehostdirection} = 1;
		}
		else
		{
			if( $DEBUG > 0 )
			{
				warn( "Unknown value of " . $cfg_hash->{ignorehostdirection} .
				" assigned to option ignorehostdirection, defaulting to true.\n" );
			}
			
			$cfg_hash->{ignorehostdirection} = 1;
		}
	}
	
	# Check to make sure the sigmap file exists, is readable and > 0 bytes.
	if( defined( $cfg_hash->{sigmapconfig} ) )
	{
		my $fn = $cfg_hash->{configdir} . '/' . $cfg_hash->{sigmapconfig};
		if( -r $fn and -s $fn )
		{
			$fn =~ m/^([[:print:]]+)$/;
			$cfg_hash->{sigmapconfig} = $1;
		}
		else
		{
			warn( "sigmapconfig file at '$fn' is not readable or zero length\n" );
			return( 0 );
		}
	}
	else
	{
		if( $cfg_hash->{updateaugment} )
		{
			warn( "No sigmapconfig file specified\n" );
			return( 0 );
		}
	}
	
	# Check if the augmentconfig option exists and validate it if it does.
	if( defined( $cfg_hash->{augmentconfig} ) )
	{
		my $fn = $cfg_hash->{configdir} . '/' . $cfg_hash->{augmentconfig};
		$fn =~ m/^([[:print:]]+)$/;
		$cfg_hash->{augmentconfig} = $1;
	}
	
	# Check if the rulesetaugmentconfig file exists and validate it if it does.
	if( defined( $cfg_hash->{rulesetaugmentconfig} ) )
	{
		my $fn = $cfg_hash->{configdir} . '/' . $cfg_hash->{rulesetaugmentconfig};
		if( -r $fn and -s $fn )
		{
			$fn =~ m/^([[:print:]]+)$/;
			$cfg_hash->{rulesetaugmentconfig} = $1;
		}
		else
		{
			warn( "rulesetaugmentconfig file at '$fn' is not readable\n" );
			return( 0 );
		}
	}
	
	# Check to make sure that sigactiondest is defined and contains valid characters
	if( ! $cfg_hash->{updateaugment} )
	{
		# {brosignaturedest}
		if( defined( $cfg_hash->{sigactiondest} ) )
		{
			if( $cfg_hash eq '' )
			{
				# ok, send to stdout
				$cfg_hash->{sigactiondest} = '';
			}
			elsif( my $fn = canwritefile( $cfg_hash->{sigactiondest} ) )
			{
				$cfg_hash->{sigactiondest} = $fn;
			}
			else
			{
				warn( "No valid --sigactiondest, unable to continue.\n" );
				return( undef );
			}
		}
		else
		{
			warn( "No filename specified for --sigactiondest\n" );
			return( undef );
		}
	}
	
	# Check to make sure that brosignaturedest is defined and contains valid characters
	if( ! $cfg_hash->{updateaugment} )
	{
		if( defined( $cfg_hash->{brosignaturedest} ) )
		{
			if( $cfg_hash eq '' )
			{
				# ok, send to stdout
				$cfg_hash->{brosignaturedest} = '';
			}
			elsif( my $fn = canwritefile( $cfg_hash->{brosignaturedest} ) )
			{
				$cfg_hash->{brosignaturedest} = $fn;
			}
			else
			{
				warn( "No valid --brosignaturedest, unable to continue.\n" );
				return( undef );
			}
		}
		else
		{
			warn( "No filename specified for --brosignaturedest\n" );
			return( undef );
		}
	}
	
	return( 1 );
}

sub getignorerules
{
	my $sub_name = 'getignorerules';
	
	my $cfg_hash = shift || return( undef );
	my $ret_hash_ref = {};
	
	if( ref( $cfg_hash->{ignoresnortrulesets} ) eq 'HASH' )
	{
		foreach my $rule_name( keys( %{$cfg_hash->{ignoresnortrulesets}} ) )
		{
			$ret_hash_ref->{$rule_name} = 1;
		}
	}
	elsif( ref( $cfg_hash->{ignoresnortruleset} ) eq 'ARRAY' )
	{
		foreach my $rule_name( @{$cfg_hash->{ignoresnortruleset}} )
		{
			$ret_hash_ref->{$rule_name} = 1;
		}
		
	}
	
	return( $ret_hash_ref );
}

sub getignoresids
{
	my $sub_name = 'getignoresids';
	
	# Argument will be a ref to an array of augment objects
	my $augment_list = shift || return( undef );
	my $ret_hash_ref = {};
	
	if( ref( $augment_list ) eq 'ARRAY' )
	{
		foreach my $aug_obj( @{$augment_list} )
		{
			if( $aug_obj->active() )
			{
				# rule is active
			}
			else
			{
				# rule is marked as not active
				my $ignore_sid = $aug_obj->sid();
				$ret_hash_ref->{$ignore_sid} = 1;
			}
		}
	}
	else
	{
		return( undef );
	}
	
	return( $ret_hash_ref );
}

sub getsnortrulefiles
{
	my $sub_name = 'getsnortrulefiles';
	
	my $rules_dir = shift || undef;
	my $exclusion_hash = shift || {};
	my @ret_file_list;
		
	if( opendir( DIR, $rules_dir ) )
	{
		while( my $fn = readdir( DIR ) )
		{
			# Make sure that the filename has only sane characters,
			 # ends with '.rules' , and does not begin with a '.'
			if( $fn =~ m/^([^.]+[[:print:]]+\.rules)$/ )
			{
				# Untaint
				$fn = $1;
				
				# Make sure the file isn't set as ignored in the config
				if( ! $exclusion_hash->{$fn} )
				{
					# expand the filename to it's full path
					my $full_fn = "$rules_dir/$fn";
					if( -f $full_fn and -r $full_fn )
					{
						push( @ret_file_list, $full_fn );
						if( $DEBUG > 4 )
						{
							warn( "Adding Snort rule file $full_fn to list of rules to convert\n" );
						}
					}
					else
					{
						if( $DEBUG > 0 )
						{
							warn( "Unable to read Snort rule file $full_fn\n" );
						}
						next;
					}
				}
				else
				{
					if( $DEBUG > 1 )
					{
						warn( "Snort ruleset \'$fn\' is being ignored as specified in the config file\n" );
					}
					next;
				}
			}
			else
			{
				next;
			}
		}
	}
	else
	{
		warn( "Unable to open Snort ruleset directory for reading at $rules_dir\n" );
	}
	
	return( \@ret_file_list );
}

sub getsigmap
{
	my $sub_name = 'getsigmap';
	
	my $sigmapfile = shift || return( undef );
	my %config;
	my $conf;
	
	if( $conf = Config::General->new( -ConfigFile => $sigmapfile,
						-LowerCaseNames => 1,
						-AutoLaunder => 1,
						-AllowMultiOptions => 'no' ) )
	{
		%config = $conf->getall;
	}
	else
	{
		warn( "Unable to read the sigmapconfig file\n" );
		return( 0 );
	}
	
	if( $DEBUG > 4 )
	{
		warn( "List of default Snort alert classtype to Bro SigAction maps:\n" );
		while( my( $key, $value ) = each( %config ) )
		{
			warn( "'$key' maps to '$value'\n" );
		}
	}
	
	return( \%config );
}

sub convertfromsnort
{
	my $sub_name = 'convertfromsnort';
	
	my $rule_files = shift || return( undef );
	my $ignore_sids = shift || return( undef );
	
	my @converted_rules;
	
	foreach my $rule_file( @{$rule_files} )
	{
		my $convert = `$SNORT_TO_BRO_PROG 2>/dev/null $rule_file`;
		if( $DEBUG > 4 )
		{
			warn( "SIGNATURES BEGIN for file $rule_file => \n" );
			warn( $convert || '' . "\n" );
			warn( "----SIGNATURES END----\n" );
		}
		
		foreach my $sig_block( Bro::Signature::findkeyblocks( $convert ) )
		{
			if( ! $sig_block )
			{
				next;
			}
			
			if( my $bro_sig_obj = Bro::Signature->new( string => $sig_block ) )
			{
				push( @converted_rules, $bro_sig_obj );
			}
			else
			{
				if( $DEBUG > 0 )
				{
					warn( "Failed to create a Bro::Signature for a rule in file $rule_file\n" );
				}
			}
		}
	}
		
	# If successful this returns an array ref of Bro::Signature objects
	return( \@converted_rules );
}

sub outputsigactions
{
	my $sub_name = 'outputsigactions';
	
	my $_sigactions = shift;
	my $_output_dest = shift || \*STDOUT;
	
	# Heading of SigAction table
	my $tm = scalar( localtime() );
	print $_output_dest "\# This file was created by s2b.pl on $tm.\n";
	print $_output_dest "\# This file is dynamically generated each time s2b.pl is" .
	" run and therefore any \n\# changes done manually will be overwritten.\n\n";
	print $_output_dest 'redef signature_actions += {' . "\n";
	
	while( my( $sigid, $sigaction ) = each( %{$_sigactions} ) )
	{
		print $_output_dest '  ["' . 
			$config->{sigprefix} . 
			$sigid . 
			'"] = ' . 
			$sigaction . 
			",\n";
	}
	
	# ending of SigAction table
	print $_output_dest '}; ' . "\n";
}

sub outputsigs
{
	my $sub_name = '';
	
	my $_sig_objs = shift;
	my $_output_dest = shift || \*STDOUT;
	
	my $tm = scalar( localtime() );
	print $_output_dest "\# This file was created by s2b.pl on $tm.\n";
	print $_output_dest "\# This file is dynamically generated each time s2b.pl is" .
	" run and therefore any \n\# changes done manually will be overwritten.\n\n";
	
	foreach my $sig( @{$_sig_objs} )
	{
		print $_output_dest $sig->output( sigprefix => $config->{sigprefix} ), "\n\n";
	}
}

sub getrulesetaugment
{
	my $sub_name = 'getrulesetaugment';
	
	my $raf = shift || return( undef );	# ruleset augment file
	my $ret_hash;
	
	if( $DEBUG > 2 )
	{
		warn( "Attempting to parse the ruleset augment file at \'$raf\'\n" );
	}
	
	my $conf = Config::General->new( -ConfigFile => $raf,
						-LowerCaseNames => 1,
						);
	
	my %config = $conf->getall;
	
	while( my( $key, $value ) = each( %config ) )
	{
		if( $DEBUG > 2 )
		{
			warn( "Looking for augment data for ruleset $key\n" );
		}
		
		if( keys( %{$value} ) > 0 )
		{
			while( my( $opt, $opt_val ) = each( %{$value} ) )
			{
				$ret_hash->{$key}->{$opt} = $opt_val;
				if( $DEBUG > 2 )
				{
					warn( "  Found option $opt\n" );
				}
			}
		}
		else
		{
			if( $DEBUG > 2 )
			{
				warn( "No augment data found\n" );
			}
		}
	}
	
	return( $ret_hash );
}

sub buildaugment
{
	my $sub_name = 'buildaugment';
	
	my $rulesets = shift || return( undef );
	my $sigmap = shift || return( undef );
	my $default_sigaction = shift || $DEFAULT_CONFIG{defaultsigaction};
	my $ret_aug_objs = {};
	
	foreach my $rule_file( @{$rulesets} )
	{
		if( open( IN_FILE, $rule_file ) )
		{
			my $full_line = '';
			my $line_num = 0;
			while( defined( my $line = <IN_FILE> ) )
			{
				++$line_num;
				my $end_of_rule = 0;
				if( $line =~ m/^[[:space:]]\#/
					or $line =~ m/^[[:space:]]*$/ )
				{
					# ignore this line, it's all comments or whitespace
					next;
				}
				else
				{
					if( $line =~ m/^(alert.+)/ )
					{
						$line = $1;
						if( $line =~ m/^(.+?)[[:space:]]*\\[[:space:]]*$/ )
						{
							$full_line = join( ' ', $full_line, $1 );
						}
						elsif( $full_line )
						{
							$full_line = join( ' ', $full_line, $line );
							$end_of_rule = 1;
						}
						else
						{
							$full_line = $line;
							$end_of_rule = 1;
						}
					}
					else
					{
						# Snort action is not supported for conversion
						next;
					}
				}
				
				if( $end_of_rule )
				{
					# Extract the directives section
					if( $full_line =~ m/\((.+)\)/ )
					{
						my $sigaction;
						my %directive_args;
						my @new_aug_objs;
						my $directive_section = $1;
						my @directives = split( /[[:space:]]*\;[[:space:]]*/, $directive_section );
						foreach( @directives )
						{
							# split the directive name from it's value
							my( $directive_name, $directive_value ) = split( /:[[:space:]]*/, $_, 2 );
							if( defined( $directive_name ) and defined( $directive_value ) )
							{
								$directive_args{$directive_name} = $directive_value;
								#print "DIRECTIVE => ", $directive_name;
								#print ", VALUE => ", $directive_value, "\n";
							}
						}
						
						# translate the snort event classtype to a Bro SigAction
						if( $sigmap->{$directive_args{classtype}} )
						{
							# ok, found one
							$sigaction = $sigmap->{$directive_args{classtype}};
						}
						else
						{
							# Didn't find a mapping, using the default
							$sigaction = $default_sigaction;
							
							if( $DEBUG > 0 )
							{
								warn( "No Snort classtype to Bro SigAction mapping found",
								 " for classtype " . $directive_args{classtype} . " using default",
								 " of $default_sigaction\n" );
							}
						}
						
						# create a new augment object with the directive parts
						 # we are interested in.
						my $new_aug_obj = Bro::S2b::Augment->new( 
							'sid' => $directive_args{sid},
							'snort-rule-file' => $rule_file,
							'sid-rev' => $directive_args{rev},
							'comment' => $directive_args{msg},
							'active' => 'T',
							'sigaction' => $sigaction,
							);
						
						#print $new_aug_obj->output(), "\n\n";
						my $new_aug_sigid = $new_aug_obj->sigid();
						my $new_aug_sid = $new_aug_obj->sid();
						my $new_aug_rev = $new_aug_obj->rev();
						if( exists( $ret_aug_objs->{$new_aug_sigid} ) )
						{
							if( $DEBUG > 0 )
							{
								warn( "Duplicate augment block found for SID number",
									" $new_aug_sid, rev $new_aug_rev\n" );
							}
						}
						else
						{
							$ret_aug_objs->{$new_aug_sigid} = $new_aug_obj;
						}
					}
					else
					{
						warn( "Could not find a diretives section for Snort rule in",
						 " file $rule_file at line $line_num\n" );
					}
					
					$full_line = '';
					$end_of_rule = 0;
				}
			}
			
			close( IN_FILE );
		}
		else
		{
			warn( "Failed to open file $rule_file for reading while trying to",
				" update the augment file\n" );
		}
	}
	
	my @ret_vals = values( %{$ret_aug_objs} );
	
	return( \@ret_vals );
}

sub appendaugment
{
	my $sub_name = 'appendaugment';
	
	my $aug_obj = shift || return( undef );
	my $filename = shift || return( undef );
	my @proc_objs;
	
	if( ref( $aug_obj ) eq 'ARRAY' )
	{
		@proc_objs = @{$aug_obj};
	}
	else
	{
		$proc_objs[0] = $aug_obj;
	}
	
	if( open( OUTFILE, '>>', $filename ) )
	{
		my $tm = scalar( localtime() );
		print OUTFILE '##########  Start of new augment data created on ' . "$tm\n";
		foreach my $aug_inst( @proc_objs )
		{
			print OUTFILE $aug_inst->output(), "\n\n";
		}
		print OUTFILE '##########  End of new augment data created on ' . "$tm\n\n";
	}
	else
	{
		if( $DEBUG > 0 )
		{
			warn( "Unable to open file $filename for writing.\n" );
		}
		return( undef );
	}
	
	close( OUTFILE );
	
	return( 1 );
}


sub sigidnum
{
	# The sidnum is assumed to be the first part before the last '-' 
	 # and up to but not including '-'
	 # s2b-123-1   prefix-sidnum-sidrev
	my $sub_name = 'sigidnum';

	my $sigid = shift || return( undef );
	my $ret_sid;

	if( $sigid =~ m/([[:digit:]]+)-[[:digit:]]+$/ )
	{
		$ret_sid = $1;
	}

	return( $ret_sid );
}

sub sigidrev
{
	# The sidrev is assumed to be the last part of the sigid after a '-'
	 # s2b-123-1   prefix-sidnum-sidrev
	my $sub_name = 'sigidrev';

	my $sigid = shift || return( undef );
	my $ret_rev;

	if( $sigid =~ m/[[:digit:]]+-([[:digit:]]+)$/ )
	{
		$ret_rev = $1;
	}

	return( $ret_rev );
}

sub canwritefile
{
	my $sub_name = 'canwritefile';
	
	my $filename = shift;
	my $ret_fn;
	
	if( $filename =~ m/^([[:print:]]+)$/ )
	{
		my $fn = $1;
		my $dir = $fn;
		$dir =~ s/[^\/]+$//;
		if( length( $dir ) < 1 )
		{
			$dir = './';
		}

		# Check to make sure that the file can be created/written to.
		# Does the file already exist and can be written to
		if( -w $fn )
		{
			# ok.
			$ret_fn = $fn;
		}
		# Is the directory writtable
		elsif( -d $dir and -w $dir )
		{
			# ok.
			$ret_fn = $fn;
		}
		# Blow chunks
		else
		{
			warn( "Unable to create or modify file '$fn'\n" );
		}
	}
	else
	{
		warn( "Filename contains non-printable characters and is invalid.\n" );
	}
	
	return( $ret_fn );

}

sub usage
{
	my $sub_name = 'usage';
	
	my $usage_text = copyright();
	$usage_text = qq~$usage_text

Options passed to the program on the command line 
Command line reference
  --configdir         Directory containing the various configuration files
  --mainconfig        Main configuration file
  --augmentconfig     Filename of System Augment Config file
  --useraugmentconfig Filename of the User Augment Config file
  --rulesetaugmentconfig
                      Filename of the Ruleset Augment Config file
  --sigmapconfig      Filename of Mappings for Snort alert classtype to 
                      Bro SigAction
  --brosignaturedest  Filename to write the Bro signatures to
  --defaultsigaction  Default Bro SigAction 
  --sigactiondest     Filename to write the SigActions to
  --snortrulesetdir   Directory containing Snort rules
  --ignorehostdirection
                      Ignore Snort connection direction information and
                      do not include in the Bro signature. default 'true'
  --updateaugment     Build or update the s2b-augment.cfg file using rulesets
                      found in --snortrulesdir 
  --usage|--help|-h   Summary of command line options
  --debug|-d          Specify the debug level from 0 to 5. default 1
  --version           Output the version numberto STDOUT
  --copyright         Output the copyright info to STDOUT
  
~;
	
	return( $usage_text );
}

sub version
{
	my $sub_name = 'version';
	
	return( $VERSION );
}

sub copyright
{
	my $sub_name = 'copyright';
	
	my $copyright =
qq~s2b.pl
version $VERSION, Copyright (C) 2004 Lawrence Berkeley National Labs, NERSC
Written by Roger Winslow~;
	
	return( $copyright );
}

