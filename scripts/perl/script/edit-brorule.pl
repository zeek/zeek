#!/usr/bin/perl -w

BEGIN
{
	require 5.006_001;
	use strict;
	use vars qw( $VERSION
				$DEBUG
				$DEFAULT_CONFIG
				$RFC3339_REGEX
				$TEMP_DIR_NAME
				$DEFAULT_BRO_CONFIG_FILE
				@BRO_RULE_FILES
				$BRO_CONFIG_FILE );
	
	use Getopt::Long;
	Getopt::Long::Configure ( 'bundling', 'no_getopt_compat', 'pass_through', 'no_ignore_case' );
	use Bro::Config qw( $BRO_CONFIG );
	
	
	$DEFAULT_BRO_CONFIG_FILE = '/usr/local/bro/etc/bro.cfg';
	$BRO_CONFIG_FILE = getbroconfigfile() || $DEFAULT_BRO_CONFIG_FILE;
	Bro::Config::Configure( File => $BRO_CONFIG_FILE );
	
	sub getbroconfigfile
	{
		my $sub_name = 'getbroconfigfile';
		
		my %cmd_line_cfg;
		
		GetOptions( \%cmd_line_cfg,
				'broconfig|b=s' );
		
		return( $cmd_line_cfg{broconfig} );
	}
}

# $Id: edit-brorule.pl 5222 2008-01-09 20:05:27Z vern $
$VERSION = 1.20;
use Time::Local;
use Bro::Signature qw( findkeyblocks getrules utctimenow );

%{$DEFAULT_CONFIG} = ( temp => '/tmp',
					editor => 'vi',
					'require_write' => 0,);
my $temp_prefix = 'edit-brorule';
my $config = getconfig();
my $temp_file = $config->{temp} . '/' . $temp_prefix . $$ . '.tmp';

$RFC3339_REGEX = qr/^([[:digit:]]{4})			# year
					-([[:digit:]]{2})		# month
					-([[:digit:]]{2})		# day
					(?:[Tt ]					# begin time section
					([[:digit:]]{2})		# hour
					(?::([[:digit:]]{2})	# minute
					(?::([[:digit:]]{2}(\.[[:digit:]]{1,2})?)|)|)	# second
					)?					# end time section
					([Zz]|([-+][[:digit:]]{2}:[[:digit:]]{2}))?	# timezone offset
					$/xo;


########### Begin main here #################

# Set the list of Bro rule files which will be used
if( exists( $config->{addpath} ) and $config->{addpath} )
{
	@BRO_RULE_FILES = Bro::Signature::filelist( @{$config->{addpath}} );
}
elsif( exists( $config->{ruledir} ) and $config->{ruledir} )
{
	@BRO_RULE_FILES = Bro::Signature::filelist( mode => 'override', $config->{ruledir} );
}
elsif( exists( $config->{rulefile} ) and $config->{rulefile} )
{
	@BRO_RULE_FILES = ( $config->{rulefile} );
}
else
{
	@BRO_RULE_FILES = Bro::Signature::filelist();
}

# If there are no rule files then no need to continue any further
if( @BRO_RULE_FILES < 1 )
{
	warn( "Unable to find any Bro signature files to edit\n" );
	exit( 1 );
}

# If any option which edits a signature is called then the rules files
# must be writtable.
if( $config->{require_write} )
{
	foreach my $rule_file( @BRO_RULE_FILES )
	{
		if( ! -w $rule_file )
		{
			warn( "Do not have write access on Bro signature file $rule_file\n" );
			warn( "Must have write access to continue. Resolve this issue and then try again\n" );
			exit( 1 );
		}
	}
}

# Check if the temp file already exists.  If so it must be writtable
if( -f $temp_file and ! -w $temp_file )
{
	warn( "Temp file $temp_file already exists and is not writtable.\n" );
	warn( "Please resolve the problem and try again.\n" );
	exit( 1 );
}


# How were we called.

# These options will require a temp file for writting.
if( exists( $config->{disable} ) )
{
	changeactivestatus( 'false', @{$config->{disable}} );
}
elsif( exists( $config->{enable} ) )
{
	changeactivestatus( 'true', @{$config->{enable}} );
}

if( $config->{edit} )
{
	if( ! editbrorule( @{$config->{edit}} ) )
	{
		warn( "Failed to edit brorules.  No changes have been made.\n" );
		exit( 1 );
	}
}
elsif( $config->{add} )
{
	if( addbrorule( @{$config->{add}} ) )
	{
		print "Rule added successfully\n";
	}
}


exit( 0 );









############# Begin subs here ################

sub getconfig
{
	my $sub_name = 'getconfig';
	
	my $arg1 = shift || $DEFAULT_CONFIG;
	my %default_config;
	my %config;
	my $active_method = '__NULL__';
	my %clc = ( usage => 0,
				debug => 0,
				version => 0,
				copyright => 0, );
	
	if( ref( $arg1 ) eq 'HASH' )
	{
		%default_config = %{$arg1};
	}
	else
	{
		return( undef );
	}
	
	# This is kind of funky.  The subroutine set in '<>' will be called
	# when an argument unknown to the parser is encountered.  This sub
	# will handle sucking up lists that can occur after an option.  Where
	# the list is saved depends upon the option which prefixed the list
	GetOptions( 'broconfig|b' => \$clc{broconfig},
			'disable|deactivate' => sub { $active_method = 'disable'; },
			'<>' => sub { push( @{$clc{$active_method}}, @_ ); },
			'enable|activate' => sub { $active_method = 'enable'; },
			'edit|e' => sub { $active_method = 'edit'; },
			'add|a' => sub { $active_method = 'add'; },
			'rulefile=s' => \$clc{rulefile},
			'ruledir=s' => \$clc{ruledir},
			'addpath' => sub { $active_method = 'addpath'; },
			'editor=s' => \$clc{editor},
			'temp|t=s' => \$clc{temp},
			'usage|help|h' => \$clc{usage},
			'debug|verbose|d|v:+' => \$clc{debug},
			'version|V' => \$clc{version},
			'copyright' => \$clc{copyright}, );
	
	# Check for options which will prevent the program from running
	# any further
	if( $clc{usage} )
	{
		print usage();
		exit( 0 );
	}
	elsif( $clc{version} )
	{
		print version();
		exit( 0 );
	}
	elsif( $clc{copyright} )
	{
		print copyright();
		exit( 0 );
	}
	else
	{
		# just continue on
	}
	
	# Set the location in which to write temp files
	if( exists( $ENV{TEMP} ) and $ENV{TEMP} )
	{
		$config{temp} = $ENV{TEMP};
	}
	elsif( exists( $ENV{TMP} ) and $ENV{TMP} )
	{
		$config{temp} = $ENV{TMP};
	}
	
	# Set the location of the preferred text editor
	if( exists( $ENV{EDITOR} ) and $ENV{EDITOR} )
	{
		$config{editor} = $ENV{EDITOR};
	}
	
	# Set Debug level
	$DEBUG = $clc{debug};
		
	# Print the list of rules passed to enable.disable
	if( $DEBUG > 1 )
	{
		if( $clc{disable} )
		{
			print "List of rules to disable/deactivate: ";
			print join( ' ', @{$clc{disable}} );
			print "\n";
		}
		
		if( $clc{enable} )
		{
			print "List of rules to enable/activate: ";
			print join( ' ' , @{$clc{enable}} );
			print "\n";
		}
		
		if( $clc{edit} )
		{
			print "List of rules to edit: ";
			print join( ' ' , @{$clc{edit}} );
			print "\n";
		}
		
		if( $clc{addpath} )
		{
			print "List of additional directories to search: ";
			print join( ':', @{$clc{addpath}} );
			print "\n"
		}
		
		if( $clc{add} )
		{
			print "List of arguments passed to add: ";
			print join( ' ', @{$clc{add}} );
			print "\n"
		}
	}
	
	# Any args passed through the command line will override file options
	while( my( $key, $value ) = each( %clc ) )
	{
		if( defined( $value ) )
		{
			$config{$key} = $value;
		}
	}
	
	# Set default values for options that have not already been configured
	while( my( $key, $value ) = each( %{$arg1} ) )
	{
		if( ! exists( $config{$key} ) )
		{
			$config{$key} = $value;
		}
	}
	
	if( checkconfig( \%config ) )
	{
		if( $DEBUG > 4 )
		{
			warn( "Configuration memory dump:\n" );
			foreach my $key( keys( %config ) )
			{
				print "$key\t=> " . $config{$key} . "\n";
			}
			warn( "\n" );
		}
		return( \%config );
	}
	else
	{
		warn( "exiting program\n" );
		exit( 1 );
	}
	
}

sub checkconfig
{
	my $sub_name = 'checkconfig';
	
	my $config = shift || return( undef );
	my $valid_action = 0;
	my $failed = 0;
	
	# Temp directory must exist and be writtable
	if( -d $config->{temp} )
	{
		if( ! -w $config->{temp} )
		{
			warn( "Temp directory at " . $config->{temp} . " must be writtable\n" );
			$failed = 1;
		}
	}
	else
	{
		warn( "Temp directory at " . $config->{temp} . " does not exist\n" );
		$failed = 1;
	}
	
	if( my $verified_editor = seteditor( $config->{editor} ) )
	{
		$config->{editor} = $verified_editor;
	}
	else
	{
		warn( "Could not find absolute path for editor " . $config->{editor} . "\n" );
		$failed = 1;
	}
	
	# If any of these edit functions are used then set the require-write flag
	if( $config->{enable} or $config->{disable} or $config->{edit} or
		$config->{add} )
	{
		$config->{require_write} = 1;
	}
	
	# Can't have both enable and disable at the same time.
	if( ref( $config->{enable} ) eq 'ARRAY' and 
		ref( $config->{disable} ) eq 'ARRAY' )
	{
		warn( "Can not use both --enable and --disable at the same time.\n" );
		$failed = 1;
	}
	
	# Can't have both add and edit at the same time
	if( ref( $config->{edit} ) eq 'ARRAY' and
		ref( $config->{add} ) eq 'ARRAY' )
	{
		warn( "Can not use both --edit and --add at the same time.\n" );
		$failed = 1;
	}
	
	# A valid action must be given
	if( ! ( $config->{enable} or $config->{disable} or $config->{edit} or
			$config->{add} ) )
	{
		warn( "No action specified.\n" );
		print usage();
		exit( 1 );
	}
	
	# Check to make sure that the rule id and the optional file values are sane
	if( $config->{add} )
	{
		my $sigid = $config->{add}->[0];
		my $file = $config->{add}->[1];
				
		if( ! $sigid =~ m/^([[:print:]]+)$/ )
		{
			warn( "Error in sig id argument to --add, invalid value.\n" );
			$failed = 1;
		}
		
		if( $file )
		{
			# Taint clean the filename
			if( $file =~ m/^([[:print:]]+)$/ )
			{
				# filename is now taint clean.
				$config->{add}->[1] = $1;
				$file = $config->{add}->[1];
			}
			else
			{
				warn( "Error in file argument to --add, invalid file name.\n" );
				$failed = 1;
			}
			
			if( ! ( -f $file && -w $file ) )
			{
				warn( "Error in file argument to --add, file does not exist or is not writtable.\n" );
				$failed = 1;
			}
		}
	}
	
	if( $failed )
	{
		return( 0 );
	}
	else
	{
		return( 1 );
	}
}

sub changeactivestatus
{
	my $sub_name = 'changeactivestatus';
	
	my $new_status = shift || return( undef );
	my @id_list = @_;
	my %match_ids;
	my $total_num_changes = 0;
	my $type_of_change = '';
	
	# valid values for $new_status are true, false, 0, 1
	if( $new_status =~ m/^(?:0|false)$/ )
	{
		$type_of_change = 'disabled';
	}
	elsif( $new_status =~ m/^(?:1|true)$/ )
	{
		$type_of_change = 'enabled';
	}
	else
	{
		warn( "Invalid value '$new_status' passed to function $sub_name.\n" );
		print usage();
		return( undef );
	}
	
	foreach my $id( @id_list )
	{
		$match_ids{$id} = 1;
	}
	
	foreach my $rule_file( @BRO_RULE_FILES )
	{
		my $num_changes = 0;
		
		# Open a temp file for writting
		if( ! open( OUTFILE, ">$temp_file" ) )
		{
			warn( "Failed to open temp file $temp_file for writting.\n" );
			exit( 1 );
		}
		
		foreach $sig_obj( getrules( $rule_file ) )
		{
			if( exists( $match_ids{$sig_obj->sigid()} ) )
			{
				$sig_obj->active( $new_status );
				++$num_changes;
				delete( $match_ids{$sig_obj->sigid()} );
			}
			
			print OUTFILE $sig_obj->output() . "\n\n";
		}
		
		close( OUTFILE );
		
		if( $num_changes > 0 )
		{
			$total_num_changes += $num_changes;
			replacefile( $rule_file, $temp_file );
		}
		
		unlink $temp_file;
	}
	
	print "A total of $total_num_changes ids were matched and $type_of_change\n";
	
	if( keys( %match_ids ) > 0 )
	{
		print "The following ids were not found: ";
		print join( " ", keys( %match_ids ) ) . "\n";
	}
	
	return( 1 );
}

sub editbrorule
{
	my $sub_name = 'editbrorule';
	
	my @args = @_;
	my %rules_to_edit;
	my @modified_rules;
	
	# {$rule_file}{$sigid}
	my %rules_by_file;
	my %new_rules_by_file;
	my %unmatched_files;
	my $temp_size;
	my $temp_mtime;
	
	# There must be at least one bro rule to edit
	if( @args < 1 )
	{
		warn( "No Bro rules have been given to edit.\n" );
		return( undef );
	}
	
	# Put the list of rules to edit in a hash for easier matching
	foreach my $rule_id( @args )
	{
		$rules_to_edit{$rule_id} = 1;
	}
	
	foreach my $rule_file( @BRO_RULE_FILES )
	{
		my $num_changes = 0;
		
		foreach my $rule_obj( getrules( $rule_file ) )
		{
			if( exists( $rules_to_edit{$rule_obj->sigid()} ) )
			{
				# If the location option is here for any reason blow
				# it away before adding the current one.
				removefilelocation( $rule_obj );
				
				# Add in the location from which the rule came
				addfilelocation( $rule_obj, $rule_file );
			
				# Look for duplicate rules.
				if( exists( $rules_by_file{$rule_file}{$rule_obj->sigid()} ) )
				{
					warn( "Duplicate rule found in file $rule_file for rule id " .
						$rule_obj->sigid() . "\n" );
				}
				
				$rules_by_file{$rule_file}{$rule_obj->sigid()} = $rule_obj;
			}
		}
	}
	
	# If no rules to edit were found then bail.
	if( keys( %rules_by_file ) < 1 )
	{
		return( 0 );
	}
	
	if( ! open( OUTFILE, ">$temp_file" ) )
	{
		warn( "Failed to open temp file '$temp_file' for writing.\n" );
		return( undef );
	}
	
	# Output to temp file for user editing.
	foreach my $rule_file( keys( %rules_by_file ) )
	{
		foreach my $rule_obj( values( %{$rules_by_file{$rule_file}} ) )
		{
			print OUTFILE $rule_obj->output() . "\n\n";
		}
	}
	
	close( OUTFILE );
	
	# Record the mtime and size of the the current temp file
	$temp_mtime = ( stat( $temp_file ) )[9];
	$temp_size = ( stat( $temp_file ) )[7];
	
	# Open the external editor. If the editor returns anything but zero
	# there was an error.
	if( system( $config->{editor}, $temp_file ) != 0 )
	{
		warn( "An unknown error was encountered while using the external editor.\n" );
		return( undef );
	}
	
	# Check if the temp file has been modified at all.  If no changes then
	# just cleanup and return.
	if( ( stat( $temp_file ) )[9] == $temp_mtime and
		( stat( $temp_file ) )[7] == $temp_size )
	{
		unlink $temp_file;
		return( 1 );
	}
	
	# Put the new rule objects in a hash for easy matching.  Order by
	# the location option which will also be removed.
	foreach my $new_rule( getrules( $temp_file ) )
	{
		my $rule_file = $new_rule->option( '.location' );
		# Remove the location option as it only for the editor
		removefilelocation( $new_rule );
		
		$new_rules_by_file{$rule_file}{$new_rule->sigid()} = $new_rule;
		$unmatched_files{$rule_file} = 1;
	}
	
	# Any rule file name must exist in the list of files which the rules
	# came from.  In other words, no new signature file will be created.
	foreach my $cur_rule( @BRO_RULE_FILES )
	{
		if( exists( $unmatched_files{$cur_rule} ) )
		{
			delete( $unmatched_files{$cur_rule} );
		}
	}
	
	foreach my $unmatched_file( keys( %unmatched_files ) )
	{
		warn( "Bro rule file '$unmatched_file' encountered but was not in the list of" .
			" Bro rules searched.  All rules with this location will be ignored.\n" );
		delete( $new_rules_by_file{$unmatched_file} );
	}
	
	# Edit each rule file for which we have data.
	foreach my $rule_file( keys( %new_rules_by_file ) )
	{
		if( ! open( OUTFILE, ">$temp_file" ) )
		{
			warn( "Failed to open temp file $temp_file for writing.\n" );
			return( undef );
		}

		foreach my $old_rule( getrules( $rule_file ) )
		{
			if( exists( $new_rules_by_file{$rule_file}{$old_rule->sigid()} ) )
			{
				my $new_rule = $new_rules_by_file{$rule_file}{$old_rule->sigid()};
				my $compare_res = $old_rule->compare( $new_rule );
				
				if( $compare_res )
				{
					if( exists( $compare_res->{'meta'} ) )
					{
						bumprevision( $new_rule );
					}
					
					if( exists( $compare_res->{'action'} ) or 
						exists( $compare_res->{'condition'} ) )
					{
						bumpversion( $new_rule );
						resetrevision( $new_rule );
					}
					
					print OUTFILE $new_rule->output() . "\n\n";
				}
				else
				{
					# No changes
					print OUTFILE $old_rule->output() . "\n\n";
				}
				
				delete( $new_rules_by_file{$rule_file}{$old_rule->sigid()} );
			}
			else
			{
				print OUTFILE $old_rule->output() . "\n\n";
			}
		}

		close( OUTFILE );
		
		delete( $new_rules_by_file{$rule_file} );
		
		replacefile( $rule_file, $temp_file );
	}
	
	unlink $temp_file;
}

sub addbrorule
{
	my $sub_name = 'addbrorule';
	
	my $rule_id = shift || return( undef );
	my $rule_file = shift;	# optional
	
	my $sig_suffix = $BRO_CONFIG->{BRO_SIG_SUFFIX};
	my $brosite = $BRO_CONFIG->{BROSITE};
	my $failed = 0;
	
	# If no rule file then grab the first one found in $BROSITE
	if( ! $rule_file )
	{
		if( -d $brosite )
		{
			if( ! opendir( DIR, $brosite ) )
			{
				warn( "Failed to open $brosite directory $brosite for reading.\n" );
				return( undef );
			}
			
			while( my $file = readdir( DIR ) )
			{
				if( $file =~ m/^[^\.].*$sig_suffix$/ and -f "$brosite/$file" )
				{
					$rule_file = "$brosite/$file";
					last;
				}
			}
			
			closedir( DIR );
		}
		else
		{
			warn( "$brosite is either not specified or it is not a directory.\n" );
			return( undef );
		}
		
		if( ! $rule_file )
		{
			warn( "Unable to find a rule file in $brosite to add the new rule to.\n" );
			return( undef );
		}
	}
	
	# Read in the rule file and look for a duplicate rule
	foreach my $rule_obj( getrules( $rule_file ) )
	{
		if( $rule_obj->sigid() eq $rule_id )
		{
			warn( "Bro rule id $rule_id already exists, edit it or try something else.\n" );
			return( undef );
		}
	}
	
	# Create the skeleton of the new rule
	my $utc_now = utctimenow();
	my $rule_template = qq~
signature $rule_id \{
  active true
  .date-created $utc_now
\}
~;
	# Create a new rule object and add some default attributes
	my $new_rule = Bro::Signature->new( string => $rule_template );
	bumpversion( $new_rule, $utc_now );
	bumprevision( $new_rule, $utc_now );
	addfilelocation( $new_rule, $rule_file );
	
	TEMP_FILE_OPEN: {
		# Output the new rule to a temp file for editing
		if( open( OUTFILE, ">$temp_file" ) )
		{
			print OUTFILE $new_rule->output() . "\n\n";
		}
		else
		{
			warn( "Failed to open temp file '$temp_file' for writing.\n" );
			$failed = 1;
			last;
		}

		close( OUTFILE );

		# Open the external editor. If the editor returns anything but zero
		# there was an error.
		if( system( $config->{editor}, $temp_file ) != 0 )
		{
			warn( "An unknown error was encountered while using the external editor.\n" );
			$failed = 1;
			last;
		}

		# Read the rule file back in.  Only one rule should be in here.
		my @temp_rules = getrules( $temp_file );
		if( @temp_rules > 1 )
		{
			warn( "More than one rule was found in the temp file.  Only one rule at a time can be created.\n" );
			$failed = 1;
			last;
		}

		# Make sure that the rule id has not been changed.
		if( $rule_id ne $temp_rules[0]->sigid() )
		{
			warn( "The rule id has been changed, aborting add.\n" );
			$failed = 1;
			last;
		}

		# The file location is put in for convenience.  User modification will be ignored.
		removefilelocation( $temp_rules[0]->sigid() );

		# Write the new signature out to the bottom of the file
		if( open( OUTFILE, ">>$rule_file" ) )
		{
			print OUTFILE $temp_rules[0]->output() . "\n\n";
		}
		else
		{
			warn( "Failed to open rule file $rule_file for writing, rule addidtion aborted.\n" );
			$failed = 1;
			last;
		}
	}	# end TEMP_FILE_OPEN
	
	unlink $temp_file;
	
	if( $failed )
	{
		return( undef );
	}
	else
	{
		return( 1 );
	}
}

sub bumpversion
{
	my $sub_name = 'bumpversion';
	
	my $self = shift || return( undef );
	my $new_date = shift;	# optional
	
	my $cur_ver = $self->version();
	
	# If $new_date was not passed in then set it now.
	if( ! $new_date )
	{
		$new_date = utctimenow();
	}
	
	if( length( $cur_ver ) > 0 )
	{
		$self->modoption( '.version', $cur_ver + 1 );
	}
	else
	{
		$self->addoption( '.version', 1 );
	}
	
	if( ! $self->modoption( '.version-date', $new_date ) )
	{
		$self->addoption( '.version-date', $new_date );
	}
	
	return( $self->version() );
}

sub bumprevision
{
	my $sub_name = 'bumprevision';
	
	my $self = shift || return( undef );
	my $new_date = shift;	# optional
	
	my $cur_rev = $self->revision();
	
	# .version must exist!
	if( ! $self->option( '.version' ) )
	{
		bumpversion( $self, $new_date );
	}
	
	# If $new_date was not passed in then set it now.
	if( ! $new_date )
	{
		$new_date = utctimenow();
	}
	
	if( length( $cur_rev ) > 0 )
	{
		$self->modoption( '.revision', $cur_rev + 1 );
	}
	else
	{
		$self->addoption( '.revision', 1 );
	}
	
	if( ! $self->modoption( '.revision-date', $new_date ) )
	{
		$self->addoption( '.revision-date', $new_date );
	}
	
	return( $self->revision() );
}

sub resetrevision
{
	my $sub_name = 'resetrevision';
	
	my $self = shift || return( undef );
	
	if( ! $self->modoption( '.revision', 1 ) )
	{
		bumprevision( $self );
	}
	
	return( $self->revision() );
}

sub addfilelocation
{
	my $sub_name = 'addfilelocation';
	
	my $rule_obj = shift || return( undef );
	my $rule_file = shift || return( undef );
	
	# Make sure the obj is of Bro::Signature type
	if( ref( $rule_obj ) ne 'Bro::Signature' )
	{
		warn( "First arg passed to $sub_name is not a Bro::Signature object.\n" );
		return( undef );
	}
	
	if( $rule_obj->addoption( '.location', $rule_file ) )
	{
		return( 1 );
	}
	else
	{
		warn( "Failed to add file location to Bro rule " . $rule_obj->sigid() . ".\n" );
		return( undef );
	}
}

sub removefilelocation
{
	my $sub_name = 'removefilelocation';
	
	my $rule_obj = shift || return( undef );
	
	# Make sure the obj is of Bro::Signature type
	if( ref( $rule_obj ) ne 'Bro::Signature' )
	{
		warn( "First arg passed to $sub_name is not a Bro::Signature object.\n" );
		return( undef );
	}
	
	if( $rule_obj->deloption( '.location' ) )
	{
		return( 1 );
	}
	else
	{
		return( 0 );
	}
}

sub seteditor
{
	my $sub_name = 'seteditor';
	
	my $editor = shift || return( undef );
	my $clean_editor;
	my @path_list = split( /:/, $ENV{PATH} );
	
	if( $editor =~ m/^(\/[[:print:]]+)$/ )
	{
		$clean_editor = $1;
	}
	else
	{
		foreach my $dir_name( @path_list )
		{
			my $full_path = "$dir_name/$editor";
			if( -f $full_path and $full_path =~ m/^(\/[[:print:]]+)$/ )
			{
				$clean_editor = $1;
			}
		}
	}
	
	# Make sure that the file exists and is executable
	if( -f $clean_editor and -x $clean_editor )
	{
		return( $clean_editor );
	}
	else
	{
		return( undef );
	}
}

sub replacefile
{
	my $sub_name = 'replacefile';
	
	my $old_file = shift || return( undef );
	my $new_file = shift || return( undef );
	my $cp_result;
	my $_cur_pid = $$;
	
	if( system( "cp -f $new_file $old_file.$_cur_pid.tmp" ) == 0 )
	{
		if( system( "mv -f $old_file.$_cur_pid.tmp $old_file" ) == 0 )
		{
			return( 1 );
		}
		else
		{
			warn( "Failed to replace $old_file with new file $new_file\n" );
			return( undef );
		}
	}
	else
	{
		warn( "Failed to move new file $new_file to $old_file.$_cur_pid.tmp\n" );
		return( undef );
	}
}

sub normalize_time
{
	my $sub_name = 'normalize_time';
	# change various time formats into a unix epoch time with 6 decimal places
	
	my $arg1 = $_[0];
	my $ret_time;
	
	if( $arg1 =~ m/^([[:digit:]]{10}(?:\.[[:digit:]]{1,6})?)$/ )
	{
		# Already in the right format.
		$ret_time = sprintf( "%.6f", $1 );
	}
	# RFC 3339 format -> 2004-08-06T19:59:39-07:00
	elsif( my @time_parts = ( $arg1 =~ $RFC3339_REGEX ) )
	{
		my $year = $time_parts[0];
		my $mon = $time_parts[1];
		my $day = $time_parts[2];
		my $hour = $time_parts[3] || 0;
		my $min = $time_parts[4] || 0;
		my $sec = $time_parts[5] || 0;
		my $timezone = $time_parts[6] || undef;
		
		# month is zero base indexed
		if( $mon )
		{
			--$mon;
		}
		
		if( $timezone =~ m/^(?:[-+]00:00)|(?:[Zz])$/ )
		{
			$ret_time = timegm($sec,$min,$hour,$day,$mon,$year);
		}
		else
		{
			$ret_time = timelocal($sec,$min,$hour,$day,$mon,$year);
		}
	}
	else
	{
		if( $DEBUG > 0 )
		{
			warn( "Unknown date format passed to sub $sub_name. Unable to convert time to a unix epoch time\n" );
		}
	}
	
	return( $ret_time );
}

sub usage
{
	my $sub_name = 'usage';
	
	my $usage_text = copyright();
	$usage_text .= q~

Options passed to the program on the command line 
Command line reference
  --disable|--deactivate  List of bro rule ids seperated by spaces to disable
                          This is mutually exclusive to --enable
  --enable|--activate     List of bro rule ids seperated by spaces to enable
                          This is mutually exclusive to --disable
  --edit|-e               List of bro rule ids to edit. An external editor
                          will be opened and any changes made by the user will
                          be intergrated in.
  --add|-a                Add a new rule.  One rule at a time may be added.
                          Arguments to follow are the sig id and the file
                          in which to write the new sig.  If no file argument
                          is given then the first signature file in $BROSITE
                          will be used. (example --add test-sig myrules.sig)
  --rulefile              Restrict edits to only the one filename given.
  --ruledir               Restrict searches and edits to just one directory.
  --addpath               Directories to look in for bro rule files. This is
                          in addition to those already in $BROPATH
  --broconfig|-b          Alternate location containing Bro configuration data
  --editor                Location of prefered text editor
                          (default $EDITOR or vi)
  --temp                  Alternate directory in which to write temp files
                          (default $TEMP or $TMP or /tmp)
  --usage|--help|-h       Summary of command line options
  --debug|-d              Specify the debug level from 0 to 5. (default: 1)
  --version               Output the version number to STDOUT
  --copyright             Output the copyright info to STDOUT
  
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
qq~edit-brorule.pl
version $VERSION, Copyright (C) 2004 Lawrence Berkeley National Labs, NERSC
Written by Roger Winslow~;
	
	return( $copyright );
}
