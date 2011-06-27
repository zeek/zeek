#!/usr/bin/python
import csv
import sys
import re
import argparse
import functools

# This is just a simple utility to convert BRO csv files into something that the DataSeries csv2ds thingy can deal with.
# Note: DS is a binary format, which means that the type of each individual variable must be known.  Thus, the types must
# be provided to the script (as it's not cool enough to go into the appropriate bro files and extract this information).
#
# This acts on BRO files in the default ASCII format *ONLY*.  It's proof of concept.  Sorry :(
#
# TODO: Move type argument into file listed as a bunch of lines consisting of FIELD_NAME=FIELD_TYPE, perhaps?

type_abbrev = {'s':'variable32', 'i':'int32', 'I':'int64', 'd':'double', 'b':'boolean', 'c':'byte'}

def process_csv(reader, field_types, output_path):
    global verbose
    cprint(verbose, "Processing logfile...")
    csv_fd = open(output_path, "w")
    csv_writer = csv.writer(csv_fd, delimiter=',')
    for line in reader:
        write_entry = []
        for item_val, item_type in zip(line, field_types):
            if(item_val == '-' and item_type != 's'):
                write_entry.append('0')
            else:
                write_entry.append(item_val)
        csv_writer.writerow(write_entry)
    print "Logfile written to: " + output_path

def gen_schema(title, field_info, output_path):
    """
        Generates a DataSeries XML schema called 'title'
        Field info is a list of (field_name, field_type) pairs describing each individual field in the DataSeries extent
        The output path optionally specifies a place to write the XML file
    """
    global verbose
    cprint(verbose, "Generating schema...")
    cprint(verbose, "Fields: " + str(field_info))
    xmlschema = '<ExtentType name="' + title + '" version="1.0" namespace="bro-ids.org">\n'
    field_index = 0
    for field_title, field_type in field_info:
        if(field_title == ''):
            field_title = "field" + str(field_index)
            field_index += 1
        
        if(field_type in type_abbrev):
            field_type = type_abbrev[field_type]
        else:
            sys.stderr.write("Unknown field type: " + field_type + "\n")
            sys.exit(-1)

        if(field_type != 'double'):
            xmlschema += '\t<field type="' + field_type + '" name="' + field_title + '" pack_unique="yes" />\n'
        else:
            xmlschema += '\t<field type="' + field_type + '" name="' + field_title + '" />\n'
    xmlschema += '</ExtentType>\n'
    cprint(verbose, "Writing document to " + output_path)
    if(output_path != ''):
        xml_fd = open(output_path, "w")
        print >>xml_fd, xmlschema
    print "Schema written to: " + output_path

def cprint (expr, message):
    """ 
        Writes the message assuming the first condition is true
    """
    if(expr):
        print message

def autodetect_field_types (csv_entry):
    """
        Does some regex voodoo to autodetect appropriate types for each field in the
        DataSeries extent.
    """
    type_list = []
    for entry in csv_entry:
        if(re.match(r'[0123456789]+$', entry)):     # Integer value
            type_list.append('I')
            # print entry + " : I"
        elif(re.match(r'[0-9]+\.[0-9]+$', entry)):   # Floating point value
            type_list.append('d')
            # print entry + " : d"
        else:
            type_list.append('s')
            # print entry + " : s"
    return type_list

if __name__ == "__main__":
    global verbose
    parser = argparse.ArgumentParser(description='Processes a Bro logfile in its default ASCII form and tries to convert it to the DataSeries format.')
    parser.add_argument('-n', '--field-types', default='', dest='fields', help='The type of each individual field in a line of Bro\'s log output.  Example: "i,I,i,s,s,b"\
  Types: i=int32,I=int64,s=string,b=boolean,c=byte,d=double')
    parser.add_argument('-t', '--extent-title', default='GenericBroStream', dest='title', help='The name of this unique set of fields')
    parser.add_argument('-v', default=False, action='store_true', dest='verbose', help='Explain what the script is doing')
    parser.add_argument('logfiles', metavar='LOGFILE', nargs='+', help='Bro logfiles to process; all logfiles must share a common format')

    args = parser.parse_args()
    verbose = args.verbose

    cprint(verbose, 'Running against logfiles: ' + str(args.logfiles))
    for logfile in args.logfiles:
        cprint(verbose, "Processing: '" + logfile + "'")
        fd = open(logfile)
        field_names = fd.readline()
        field_types = []
        field_info = []
        log_fd = open(logfile, 'rb')
        log_reader = csv.reader(open(logfile, 'rb'), delimiter='\t')
        tlist = log_reader.next()
        row_sample = log_reader.next()
        log_fd.close()
        log_reader = csv.reader(open(logfile, 'rb'), delimiter='\t')
        if(args.fields == ''):
            field_types = autodetect_field_types(row_sample)
        else:
            field_types = args.fields.split(',')
        if(field_names[0] == "#"):
            cprint(verbose, "Pulling field names from logfile")
            field_names = field_names[1:].strip()
            field_names = field_names.split('\t')
            cprint(verbose, field_names)
        else:
            field_index = 0
            for f in tlist:
                field_index += 1
                field_names.append('field' + str(field_index))
            cprint(verbose, field_names)
        if( len(field_names) > 0 and len(field_names) != len(field_types) ):
            sys.stderr.write("Sanity check failed: number of types [" + str(len(field_names)) + "] != number of field names [" + str(len(field_types)) + "].  Use '--field-types' to specify the types for each field.\n")
            sys.exit(-1)
        for curr, info in zip(field_names, field_types):
            field_info.append( (curr, info) )
        gen_schema(args.title, field_info, str(logfile + ".xml"))
        process_csv(log_reader, field_types, str(logfile + ".csv"))
        # TODO: Handle the case where no field names are present.

