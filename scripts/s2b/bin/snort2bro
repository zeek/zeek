#!/usr/bin/python

import sys
import re
import getopt
import os.path
import struct

# FIXME: Not all of the implemented Snort options are really tested...

snortcmd       = re.compile( "(preprocessor|include|var|config|alert|log|pass|activate|dynamic|output)\s*:?\s*(.*)" )
snortrule      = re.compile( "(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\((.*)\)" )
snortopt       = re.compile( r"([a-zA-Z_]+)\s*(:\s*(([^;]|(?<=\\);)+)|);" )

snortipre      = "(\d+\.\d+\.\d+\.\d+(/\d+)?)"
snortip        = re.compile( "(!)?%s" % snortipre )
snortiplist    = re.compile( "(!)?\[(%s(,%s)*)\]" % ( snortipre,snortipre ) )
snortport      = re.compile( "(!)?(\d+)" )
snortportrange = re.compile( "(!)?(\d+)?:(\d+)?" )
snortval       = re.compile( "([<>=!]?) *(\d+)" )
snortvalrange  = re.compile( "(\d+)? *- *(\d+)?" )
snortbytecode  = re.compile( r"\\\|\s*(([a-fA-F0-9]{2}\s*)+)\s*\\\|" ) # "|" are quoted when we do the match
snorthex       = re.compile( "(..) *" )
snortquote     = re.compile( r"\\(.)" )
snortalpha     = re.compile( r"(\\x[a-fA-F0-9]{2}|[A-Za-z])" )
snortrpc       = re.compile( r"((\d)+|\*) *, *((\d)+|\*) *, *((\d)+|\*)" )

snortsid       = re.compile( "sid: *(\d+)" )
snortrev       = re.compile( "rev: *(\d+)" )

# Mapping of Snort's variables to Bro's
#     <snort> -> ( <bro>, <invert> )
MapVars = {
    "external_net": ( "local_nets", 1 ),
    "home_net": ( "local_nets", 0 ),
    "http_servers": ( "http_servers", 0 ),
    "http_ports": ( "http_ports", 0 ),
    "oracle_ports": ( "oracle_ports", 0 ),
    "smtp_servers": ( "smtp_servers", 0 ),
    "sql_servers": ( "sql_servers", 0 ),
    "telnet_servers": ( "telnet_servers", 0 ),
    "aim_servers": ( "aim_servers", 0 ),
    "shellcode_ports": ( "non_shellcode_ports", 1 ),
}

# Mapping of variables to content
SnortVars = {}

# List of tuples (file,linenr) for all not fully processed input files:
Inputs = []

# Last input line read
RawInputLine = ""

# Counts Snort rules without SID
UnknownCount = 0

# There may be some rules for which it don't make sense to translate them. We ignore them.
IgnoreSIDs = {}

# Always include these signatures, even if they would be ignored with option -c.
AlwaysIncludeSIDs = {}

def error( str ):
    if Inputs:
        if RawInputLine:
            print >>sys.stderr, ">>", RawInputLine,
            if RawInputLine[-1] != "\n":
                print >>sys.stderr
        print >>sys.stderr, "Error in %s, line %d: %s" % ( Inputs[0][0].name, Inputs[0][1], str )

    else:
        print >>sys.stderr, "Error:", str
    sys.exit( 1 )

def warning( str ):
    if Inputs:
        if RawInputLine:
            print >>sys.stderr, ">>", RawInputLine,
            if RawInputLine[-1] != "\n":
                print >>sys.stderr
        print >>sys.stderr, "Warning in %s, line %d: %s" % ( Inputs[0][0].name, Inputs[0][1], str )
    else:
        print >>sys.stderr, "Warning:", str

# Converts Snort-like globs into regexp chars
def replaceGlobs( str ):
    # Note that the globs are quoted when we see them here
    # FIXME: If the original pattern contains a "\?" or "\*" it
    # will be converted as well.
    str = str.replace( "\\*", ".*" )
    str = str.replace( "\\?", "." )
    return str

# Replaces Snort-like bytecodes by \x.. sequences
def replaceByteCodes( str ):
    return snortbytecode.sub( lambda bytecode: snorthex.sub( "\\x\\1", bytecode.group( 1 ) ), str )

# Removes Snort's \ quotations
def removeQuotes( str ):
    return snortquote.sub( "\\1", str )

# Quotes all '"'
def quoteStr( str ):
    return str.replace( "\"", "\\\"" )

# Translates all alphabetical characters to case-insensitive classes
def makeCaseInsensitive( str ):

    def replaceby( match ):
        s = match.group( 1 )
        # Do not change hex codes
        if s.startswith( "\\x" ):
            return s
        return "[%s%s]" % ( s.lower(), s.upper() )

    str = snortalpha.sub( replaceby , str )
    return str

# Insert some special variants/character classes for URIs
#     - "/ -> [/\]"
def makeURIPattern( str ):
    str = str.replace( "\\/", "[\\/\\\\]" )
    return str

# Escapes all regex control characters  so that it can be safely used as a regex
def escapeCtrl( str ):
    re = ""
    for i in str:
        if "^$|.*+?[](){}/\"\\".find( i ) >= 0:
            i = "\\" + i
        re += i
    return re

# Converts a Snort pattern into a RE
# If icase==1, constructs an case-insensitive regex.
# If uri==1, creates some special things for URIs (see above)
# If glob==1, the pattern is a Snort-like "regex" glob
# If negate==1, the pattern is negated
# If neglen>0, it's the number of character which are *not* allowed to match the negated pattern
#
# FIXME: We should use a more sophisticated parser here
#
def patternToRE( str, icase, uri, globs, negate, neglen ):

    if negate:
        if patternLength( str ) > 1:
            warning( "Can\'t negate patterns with more than one character" )
            return "<willnevermatch>"
        str = "[^%s]" % replaceByteCodes( escapeCtrl( str ) )

        if neglen > 0:
            return str + "{%d}" % neglen
        else:
            return str + "*"

    str = removeQuotes( str )
    str = escapeCtrl( str )
    if globs:
        str = replaceGlobs( str )
    str = replaceByteCodes( str )

    if uri:
        str = makeURIPattern( str )

    if icase:
        str = makeCaseInsensitive( str )

    return str

# Counts the number chars in the Snort pattern
def patternLength( str ):
    str = removeQuotes( str )
    str = escapeCtrl( str )
    str = replaceByteCodes( str )

    count = 0
    esc = 0

    for c in str:
        if c == "\\" and not esc:
            esc = 1
            continue

        if esc and c == "x":
            count -= 2

        esc = 0
        count += 1

    return count

# Parse a Snort variable declaration
def parseVar( decl ):
    ( key, value ) = decl.split()
    SnortVars[ "$"+key ] = value

# Perform Snort's variable expansion
def expandVars( str ):
    for ( key, value ) in SnortVars.items():
        str = str.replace( key, value )
    return str

# Parse Snort's rule options
def parseRuleOptions( str ):

    options = {}

    m = snortopt.findall( str )

    lastcontent = None
    depth = distance = negate = nocase = offset = regex = within = -1

    negpattern = -1

#    print str

    for ( b1, b2, b3, b4 ) in m:
        if b2:
            val = b3
            if val[0] == "!":
                negpattern = 1
                val = val[1:]
            if len( val ) >= 2:
                if val[0] == '"' and val[-1] == '"':
                    val = val[1:-1]
        else:
            val = ""

        # Note that there may be more than one depth/offset per rule.
        # Each depth/offset/regex affects exactly that content which precedes it.
        # It's illegal to have a depth/offset/regex before a content.
        # That is all undocumented.
        # ... !@#$%^&* ...

        option = b1.lower()

        if option == "content":

            if not lastcontent:
                lastcontent = val
                continue

            oldval = val
            val = ( lastcontent, depth, distance, negate, nocase, offset, regex, within )
            depth = distance = negate = nocase = offset = regex = within = -1
            negate = negpattern
            lastcontent = oldval

        elif option == "depth":
            depth = int( val )
            continue

        elif option == "distance":
            distance = int( val )
            continue

        elif option == "within":
            within = int( val )
            continue

        elif option == "offset":
            offset = int( val )
            continue

        elif option == "regex":
            regex = 1
            continue

        elif option == "nocase":
            nocase = 1
            continue

        try:
            options[ option ] += [ val ]
        except LookupError:
            options[ option ] = [ val ]

    if lastcontent:
        try:
            options[ "content" ] += [ ( lastcontent, depth, distance, negate, nocase, offset, regex, within ) ]
        except LookupError:
            options[ "content" ] = [ ( lastcontent, depth, distance, negate, nocase, offset, regex, within ) ]

    return options

# Parses a list of IPs in Snort's format
def parseIP( ip ):

    # See if it's an unexpanded var.
    if ip.startswith( "$" ):
        try:
            ( brovar, neg ) = MapVars[ ip[1:] ]
            return ( neg, [brovar] )
        except LookupError:
            error( "Unknown variable " + ip )

    m = snortip.match( ip )
    if m:
        ips = ( m.group( 2 ), )
    else:
        m = snortiplist.match( ip )
        if m:
            ips = m.group( 2 ).split( "," )
        else:
            error( "Can\'t parse IP " + ip )

    if m.group( 1 ) != "!":
        return( 0, ips )
    else:
        return( 1, ips )

# Parses a list of ports in Snort's format
def parsePort( port ):

    # See if it's an unexpanded var.
    if port.startswith( "$" ):
        try:
            ( brovar, neg ) = MapVars[ port[1:] ]
            return ( neg, brovar, brovar )
        except LookupError:
            error( "Unknown variable " + port )

    m = snortportrange.match( port )
    if m:
        try:
            min = int( m.group( 2 ) )
        except TypeError:
            min = 0
        try:
            max = int( m.group( 3 ) )
        except TypeError:
            max = 65535
    else:
        m = snortport.match( port )
        if m:
            min = max = int( m.group( 2 ) )
        else:
            error( "Can\'t parse port " + port )

    if m.group( 1 ) != "!":
        return( 0, min, max )
    else:
        return( 1, min, max )

######

# Convert the common head of a Snort rule
def convertHead( prot, srcip, srcport, dstip, dstport ):

    rule = ""

    # Convert IP protocol
    if prot.lower() != "ip":
	rule += "  ip-proto == %s\n" % prot.lower()

    # Convert IPs
    for ( tag, ip ) in ( ( "src-ip", srcip ), ( "dst-ip", dstip ) ):
        if ip != "any":
            ( negate, iplist ) = parseIP( ip )
            if not negate:
                cmp = "=="
            else:
                cmp = "!="

            rule += "  %s %s %s\n" % ( tag, cmp, ",".join( iplist ) )

    # Convert Ports
    for ( tag, port ) in ( ( "src-port", srcport ), ( "dst-port", dstport ) ):
        if port != "any":
            ( negate, min, max ) = parsePort( port )
            if min == max:
                if not negate:
                    cmp = "=="
                else:
                    cmp = "!="
                rule += "  %s %s %s\n" % ( tag, cmp, min )
            else:
                if not negate:
                    cmp1 = ">="
                    cmp2 = "<="
                else:
                    cmp1 = "<"
                    cmp2 = ">"

                rule += "  %s %s %s\n" % ( tag, cmp1, min )
                rule += "  %s %s %s\n" % ( tag, cmp2, max )

    return rule

# Converts one of Snort's bit strings (like "A+" for "flags")
def convertBitSet( str, bitspecs, hdrfield, fieldmask ):

    # Split into flags and mask
    parts = str.split(",")
    if len(parts) > 1:
        ( str, snortmask ) = parts
        # FIXME: We ignore the mask for now. This would again need some
        # digging in Snort's source as I don't really understand what they
        # are doing...
        
    # This is not strictly Snort conforming but works as long as the
    # flag string is not ambigious.

    type = ""
    mask = 0
    for c in str:
        if "+!*".find( c ) >= 0:
            type = c
            continue
        try:
            mask |= bitspecs[c]
        except LookupError:
            error( "Unknown bit in \"%s\"" % str )

    if type == "":
        # Snort's default is check for equality (undocumented)
        rule = "  %s & %d == %d\n" % ( hdrfield, fieldmask, mask )
    if type == "+":
        rule = "  %s & %d == %d\n" % ( hdrfield, ( mask | fieldmask ), mask )
    if type == "*":
        rule = "  %s & %d != 0\n" % ( hdrfield, ( mask | fieldmask ) )
    if type == "!":
        rule = "  %s & %d == 0\n" % ( hdrfield, ( mask | fieldmask ) )

    return rule

# Converts a test for a value which may include some range (e.g. "<5", "21-42")
def convertVal( str, hdrfield ):

    m = snortvalrange.match( str )
    if m:
        try:
            min = int( m.group( 1 ) )
        except TypeError:
            min = 0
        try:
            max = int( m.group( 2 ) )
        except TypeError:
            max = -1

        rule = ""
        if min > 0:
            rule += "  %s >= %d\n" % ( hdrfield, min )
        if min >= 0:
            rule += "  %s <= %d\n" % ( hdrfield, max )
        return rule

    m = snortval.match( str )
    if m:
        val = int( m.group( 2 ) )
        cmp = m.group( 1 )

        if cmp == "<" or cmp == ">":
            return "  %s %s %d\n" % ( hdrfield, cmp, val )
        if cmp == "!":
            return "  %s != %d\n" % ( hdrfield, val )
        if cmp == "" or cmp == "=":
            return "  %s == %d\n" % ( hdrfield, val )

    error( "Can\'t parse value \"%s\"" % str )

# Convert one value of the RPC triple into a RE
def convertRPCVal( str ):
    if str == "*":
        return "."
    else:
        # Convert value to hex pattern in network bye order
        val = struct.pack( "!I", int( str ) )
        return ( "\\x%02x" * 4 ) % struct.unpack( "BBBB", val )

# Sanity check to see if the two protocols match
def checkProt( testprot, option, ruleprot ):
    if testprot != ruleprot:
        error( "Option \"%s\" only valid for %s rules" % ( option, testprot.upper() ) )

def convertOptions( options, prot ):

    global IsPayloadRule
    
    rule = ""
    payloads = []

    for ( key, vallist ) in options.items():

        if key == "ack":
            checkProt( "tcp", key, prot )
            rule += "  header tcp[8:4] == %d\n" % int( vallist[0] )

        elif key == "classtype":
            pass

        elif key == "content":

           IsPayloadRule = 1
           
           for i in range( len( vallist ) ):

                ( content, depth, distance, negate, nocase, offset, regex, within ) = vallist[i]

                # Special case: If have we have a payload size which equals the size of the pattern,
                # the payload has to match exactly

                prefix = ".*"

                if "dsize" in options.keys():
                    try:
                        if patternLength( content ) == int( options["dsize"][0] ):
                            prefix = ""
                    except ValueError:
                        # dsize is something which contains a range; do nothing as
                        # it's just an optimization after all
                        pass

                realdepth = depth;
                realoffset = offset;

                maxdist = 1

                if depth >= 0:
                    realdepth -= patternLength( content )

                if offset >= 0:
                    realoffset -= 1
                    maxdist = 0

                if offset >= 0 and depth >= 0:
                    realdepth -= offset
                    maxdist = 1

                if within >= 0:
                    realdepth += within - patternLength( content ) + 1

                if distance >= 0:
                    realoffset += distance + 1
                    maxdist = 0

                if within >= 0 and distance >= 0:
                    maxdist = 1

                if realdepth < 0 and realoffset <= 0:
                    re = prefix
                else:
                    re = ""

                if realdepth < 0:
                    realdepth = -1

                if realoffset > 0:
                    if maxdist:
                        re += ".{%d}" % realoffset
                    else:
                        re += ".{%d}.*" % realoffset
                elif realoffset == 0 and not maxdist:
                        re += ".*"

                if realdepth > 0 and negate < 0:
                    re += ".{0,%d}" % realdepth
                    maxdist = 1

                re += patternToRE( content, nocase >= 0, 0, regex >= 0, negate >= 0, realdepth + 1 )

                if distance >= 0 or within >= 0:
                    try:
                        payloads[-1] += re
                    except LookupError:
                        payloads = [ re ]
                else:
                    payloads += [ re ]

                if REFile:
                    print >>REFile, re
                if PatternFile:
                    print >>PatternFile, val

        elif key == "depth":
            # Ignore it here; we test for it when handling content
            pass

        elif key == "distance":
            # Ignore it here; we test for it when handling content
            pass

        elif key == "dsize":
            rule += convertVal( vallist[0], "payload-size" )
            pass

        elif key == "flags":
            checkProt( "tcp", key, prot )

            TCPFlags =  { "F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
                          "A": 0x10, "U": 0x20, "2": 0x40, "1": 0x80, "0": 0x00 }
            rule += convertBitSet( "".join( vallist ), TCPFlags, "header tcp[13:1]", 0xff )

        elif key == "flow":
            checkProt( "tcp", key, prot )

            Flows = { "established" : "established",
                      "to_server" : "originator",
                      "to_client" : "responder",
                      "from_server" : "responder",
                      "from_client" : "originator",
                      "stateless" : "stateless"
                      }

            tcpstate = []
            for val in vallist:
                for ( snort, bro ) in Flows.items():
                    if val.find( snort.lower() ) >= 0:
                        tcpstate += ( bro, )
            if tcpstate:
                rule += "  tcp-state %s\n" % ",".join( tcpstate )

        elif key == "fragbits":
            FragFlags = { "M": 0x20, "D": 0x40, "R": 0x80 }
            rule += convertBitSet( "".join( vallist ), FragFlags, "header ip[6:1]", 0xe0 )

        elif key == "icmp_seq":
            checkProt( "icmp", key, prot )
            # Check if it's an ECHO or ECHO_REPLY packet
            # Note Snort's undocumented behaviour: It does check REPLYs
            # as well, and it does not check the ICMP code
            rule += "  header icmp[0:1] == 0,8\n"
            rule += "  header icmp[6:2] == %d\n" % int( vallist[0] )

        elif key == "icmp_id":
            checkProt( "icmp", key, prot )
            # Check if it's an ECHO or ECHO_REPLY packet
            # Note Snort's undocumented behaviour: It does check REPLYs
            # as well, and it does not check the ICMP code
            rule += "  header icmp[0:1] == 0,8\n"
            rule += "  header icmp[4:2] == %d\n" % int( vallist[0] )

        elif key == "icode":
            checkProt( "icmp", key, prot )
            rule += "  header icmp[1:1] == %d\n" % int( vallist[0] )

        elif key == "id":
            rule += "  header ip[4:2] == %d\n" % int( vallist[0] )

        elif key == "ip_proto":
            rule += convertVal( vallist[0], "header ip[9:1]" )

        elif key == "ipopts":
            rule += "  ip-options %s\n" % ",".join( vallist ).lower()

        elif key == "itype":
            checkProt( "icmp", key, prot )
            rule += "  header icmp[0:1] == %d\n" % int( vallist[0] )

        elif key == "msg":
            rule += "  event \"%s\"\n" % quoteStr( removeQuotes( " ".join( vallist ) ) )

        elif key == "nocase":
            # Ignore it here; we test for it when handling content
            pass

        elif key == "offset":
            # Ignore it here; we test for it when handling content
            pass

        elif key == "rawbytes":
            # We can ignore this as we're always matching raw bytes.
            pass
        
        elif key == "ref":
            pass

        elif key == "reference":
            pass

        elif key == "regex":
            pass

        elif key == "rev":
            pass

        elif key == "rpc":
            m = snortrpc.match( vallist[0] )
            if not m:
                error( "Can\'t parse RPC values" )
            ( app, proc, version ) = ( m.group( 1 ), m.group( 3 ), m.group( 5 ) )

            # The Snort rule set has only explicit UDP/TCP rules containg
            # "rpc" but no general IP rules. So we use the rule type
            # to decide whether we check for UDP- or TCP-style RPC
            #
            # Snort only looks at calls, but not on replies (undocumented)
            # Snort validates the RPC_MSG_VERSION (undocumented)
            if prot == "udp":
                off = 7
            else:
                checkProt( "tcp", key, prot )
                off = 11

            # RPC version == 2, Call == 1 \
            rule += "  payload /" + ( "." * off ) \
                    + "\\x00\\x00\\x00\\x02\\x00\\x00\\x00\\x01"  \
                    + convertRPCVal( app ) + convertRPCVal( version ) + convertRPCVal( proc ) \
                    + "/\n"

        elif key == "sameip":
            rule += "  same-ip\n"

        elif key == "seq":
            checkProt( "tcp", key, prot )
            rule += "  header tcp[4:4] == %d\n" % int( vallist[0] )

        elif key == "sid":
            pass
        
        elif key == "rev":
            pass
        
        elif key == "tag":
            # In Snort, this capture packets of session/host for later analysis.
            # Unsupported for now, but we could come up with something similar
            # by passing it on to set_record_contents(). Doesn't affect the
            # matching, though.
            pass

        elif key == "ttl":
            rule += convertVal( vallist[0], "header ip[8:1]" )
            pass

        elif key == "uricontent":
            
           IsPayloadRule = 1            
            
           for val in vallist:
#                if ALTERNATIVE_PATTERNS:
#                    re = "(|.*\\r\\n\\r\\n)(GET|HEAD|POST) *[^\\n]*%s" % patternToRE( val, "nocase" in options.keys(), 1, 0 )
#                else:
#                    re = "(GET|HEAD|POST) *[^\\n]*%s" % patternToRE( val, "nocase" in options.keys(), 1, 0 )
#
#                rule += "  payload /%s/\n" % re

                if ALTERNATIVE_PATTERNS:
                    re = "(|.*\\r\\n\\r\\n)(GET|HEAD|POST) *[^\\n]*%s" % patternToRE( val, "nocase" in options.keys(), 1, 0, 0, 0 )
                    rule += "  payload /%s/\n" % re
                else:
                    re = ".*%s" % patternToRE( val, "nocase" in options.keys(), 1, 0, 0, 0 )
                    rule += "  http /%s/\n" % re



                if REFile:
                    print >>REFile, re
                if PatternFile:
                    print >>PatternFile, val

        elif key == "within":
            # Ignore it here; we test for it when handling content
            pass

        else:
            warning( "Option '%s' not supported currently; ignored" % key )
            rule += "  # Not supported: %s: %s\n" % ( key, ",".join( vallist ) )

    for p in payloads:
        rule += "  payload /%s/\n" % p

    return rule

def parseAlert( rule ):

    global UnknownCount
    global IsPayloadRule

    IsPayloadRule = 0
    
    m = snortrule.match( rule )
    if not m:
        error( "Can\'t parse alert rule" )

    fields = m.groups()

    ( prot, srcip, srcport, dir, dstip, dstport ) = map( lambda s: s.lower(), fields[0:6] )

    options = parseRuleOptions( fields[6] )

    try:
        sid = options["sid"][0]
        rev = options["rev"][0]
        try:
            if int( sid ) in  IgnoreSIDs:
                return
#            id = "sid-" + sid
# 2004-06-21, rwinslow, Added rev level for sid
            id = sid + "-" + rev
        except ValueError:
            id = sid

    except LookupError:
        id = "sid-unknown-%d" % UnknownCount
        UnknownCount += 1

    try:
        # Create rules depending on the direction; for "<>" we simply create
        # two rules

        #if dir == "<>":
        #    id1 = id + "-a"
        #    id2 = id + "-b"
        #else:
        #    id1 = id2 = id
				
				id1 = id2 = id
				
				if dir == "<>":
						rule = "signature %s {\n" % id1
						rule += convertHead( prot, "any", dstport, "any", srcport )
						rule += convertOptions( options, prot )
						
						if not PAYLOAD_ONLY or IsPayloadRule or id in AlwaysIncludeSIDs:
							print rule + "  }\n"
				else:
						if dir != "->":
								rule = "signature %s {\n" % id1
								rule += convertHead( prot, dstip, dstport, srcip, srcport )
								rule += convertOptions( options, prot )
								
								if not PAYLOAD_ONLY or IsPayloadRule or id in AlwaysIncludeSIDs:
										print rule + "  }\n"

						if dir != "<-":
								rule = "signature %s {\n" % id2
								rule += convertHead( prot, srcip, srcport, dstip, dstport )
								rule += convertOptions( options, prot )
								
								if not PAYLOAD_ONLY or IsPayloadRule or id in AlwaysIncludeSIDs:
										print rule + "  }\n"
        	

    except LookupError, e:
        error( "Can\'t convert rule: " + str( e ) )

#### Main

# Use some alternative patterns
ALTERNATIVE_PATTERNS = 0
# If PatternFile is a file, all content/uricontent patterns are written to it
PatternFile = 0
# If REFile is a file, all REs generated from content/uricontent patterns are written to it
REFile = 0
# Directories where to look for include's
INCPATH = [ "./" ]
# Only include signatures which match contain payload/uricontent
# (Exceptions can be defined in AlwaysIncludeSIDs)
PAYLOAD_ONLY = 0

# Number of Snort rules to output (no conversion to Bro format)
SnortRules = -1

# Total number of rules
TotalRules = 0

def openInputFile( filename ):

    for i in INCPATH:
        try:
            fullpath =  os.path.join( i, filename )
            file = open( fullpath )
            print >>sys.stderr, "Reading", fullpath
            return file
        except IOError:
            pass

    error( "Can\'t find file %s" % filename )

def ReadConfig( file ):
    
    try:
        cfg = open( arg )
        for line in cfg:
            
            line = line.strip()
            if len( line ) == 0 or line.startswith("#"):
                continue

            try:
                ( action, sid ) = line.split()
                sid = int( sid )
            except ValueError:
                print >>sys.stderr, "Warning: illegal format '%s'" % line
                continue
            
            if action == "ignoresid":
                IgnoreSIDs[sid] = 1
                
    except IOError:
        print >>sys.stderr, "Warning: Can't read config file %s" % arg
                
def usage():
    print >>sys.stderr
    print >>sys.stderr, "Usage: snort2bro [<options>] [<snort-files>] "
    print >>sys.stderr
    print >>sys.stderr, "  Options:"
    print >>sys.stderr
    print >>sys.stderr, "    -c <file>: File containing signature in-/excludes"
    print >>sys.stderr, "    -p       : Only include signatures which match on payload"
    print >>sys.stderr, "    -I <dir> : Add dir to search path for Snort\'s include statement"
    print >>sys.stderr
    print >>sys.stderr, "    -P       : Write all patterns to patterns.txt and "
    print >>sys.stderr, "               all generared REs to res.txt"
    print >>sys.stderr, "    -S <n>   : No conversion; just print out one big Snort config file"
    print >>sys.stderr, "               containing the first <n> rules"
    print >>sys.stderr, "    -X       : Produce some alternate REs"

    print >>sys.stderr
    sys.exit( 1 )

try:
    options, rest = getopt.getopt( sys.argv[1:], "XPI:S:pc:" )
except:
    usage()

for( opt, arg ) in options:
    if opt == "-X":
        ALTERNATIVE_PATTERNS = 1

    if opt == "-P":
        PatternFile = open( "patterns.txt", "w" );
        REFile = open( "res.txt", "w" );

    if opt == "-I":
        INCPATH += [ arg, ]

    if opt == "-S":
        SnortRules = int( arg )

    if opt == "-p":
        PAYLOAD_ONLY = 1

    if opt == "-c":
        ReadConfig( arg )
        
if len( rest ):
    Inputs = [ ( openInputFile( file ), 0 ) for file in rest ]
else:
    Inputs = [ ( sys.stdin, 0 ) ]

continued = False

while Inputs:

    if not continued:
        line = ""
    
    RawInputLine = Inputs[0][0].readline()
    if not RawInputLine:
        Inputs = Inputs[1:]
        continue

    single_line = RawInputLine.strip()
    
    # Increase line count
    Inputs[0] = ( Inputs[0][0], Inputs[0][1] + 1 )

    # Continuation of lines
    if single_line.endswith("\\"):
        line += single_line[:-1]
        continued = True
        continue

    line += single_line
    continued = False

    # Empty or comments
    if not line or line.startswith( '#' ):
        continue
            
    line = expandVars( line )

    m = snortcmd.match( line )
    if not m:
        error( "Can\'t parse line " + line )

    cmd = m.group( 1 )
    args = m.group( 2 )

    if cmd == "include":
        Inputs = [ ( openInputFile( args ), 0 ) ] + Inputs
        continue

    if cmd == "var":
        parseVar( args )

    if cmd == "alert":
        TotalRules += 1

    if SnortRules >= 0:

        noprint = 0

        if cmd == "alert":

            for i in IgnoreSIDs:
                m = snortsid.search( args )
                if m and int( m.group( 1 ) ) == i:
                    noprint = 1
                    
            if SnortRules == 0:
                noprint = 1

            if not noprint:
                SnortRules -= 1

        if not noprint:
            print RawInputLine,

        continue

    if cmd == "var":
        continue

    if cmd == "alert":
        parseAlert( args )
        continue

    if cmd == "output":
        continue

    if cmd == "preprocessor":
        continue

    if cmd == "config":
        # FIXME: Should we convert this to Bro?
        continue

    warning( "'%s' is not supported yet; line ignored." % cmd )


# Options -S returns the number of rules as exit code
if SnortRules >= 0:
    print >>sys.stderr, TotalRules
