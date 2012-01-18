#! /usr/bin/env python

# This script automatically generates a reST documents that lists
# a collection of Bro scripts that are "grouped" together.
# The summary text (##! comments) of the script is embedded in the list
#
# 1st argument is the file containing list of groups
# 2nd argument is the directory containing ${group}_files lists of
#   scripts that belong to the group and ${group}_doc_names lists of
#   document names that can be supplied to a reST :doc: role
# 3rd argument is a directory in which write a ${group}.rst file (will
#   append to existing file) that contains reST style references to
#   script docs along with summary text contained in original script

import sys
import os
import string

group_list = sys.argv[1]
file_manifest_dir = sys.argv[2]
output_dir = sys.argv[3]

with open(group_list, 'r') as f_group_list:
    for group in f_group_list.read().splitlines():
        #print group
        file_manifest = os.path.join(file_manifest_dir, group + "_files")
        doc_manifest = os.path.join(file_manifest_dir, group + "_doc_names")
        src_files = []
        doc_names = []

        with open(file_manifest, 'r') as f_file_manifest:
            src_files = f_file_manifest.read().splitlines()

        with open(doc_manifest, 'r') as f_doc_manifest:
            doc_names = f_doc_manifest.read().splitlines()

        for i in range(len(src_files)):
            src_file = src_files[i]
            #print "\t" + src_file
            summary_comments = []
            with open(src_file, 'r') as f_src_file:
                for line in f_src_file:
                    sum_pos = string.find(line, "##!")
                    if sum_pos != -1:
                        summary_comments.append(line[(sum_pos+3):])
            #print summary_comments
            group_file = os.path.join(output_dir, group + ".rst")
            if not os.path.exists(group_file):
                if not os.path.exists(os.path.dirname(group_file)):
                    os.makedirs(os.path.dirname(group_file))
                with open(group_file, 'w') as f_group_file:
                    f_group_file.write(":orphan:\n\n")
                    title = "Package Index: %s\n" % os.path.dirname(group)
                    f_group_file.write(title);
                    for n in range(len(title)):
                        f_group_file.write("=")
                    f_group_file.write("\n");

            with open(group_file, 'a') as f_group_file:
                f_group_file.write("\n:doc:`/scripts/%s`\n" % doc_names[i])
                for line in summary_comments:
                    f_group_file.write("   " + line)
