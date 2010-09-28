# Usage:
#
# grep "^word_in_reply" ftp-anon.log |
# grep -v "ty=ip" |
# sort -k 3 -k 2 -k 5 -n -r |
# awk -f make-ftp-safe-vocabulary.awk -
#
# grep "^word_in_reply" ftp-anon.log | grep -v "ty=ip" | awk -f make-ftp-safe-vocabulary.awk - | sort

BEGIN	{
    FS = ",";
	print "redef safe_ftp_word += {"
	}

	{
	printf("# \t%s, \t\t# %s, %s, %s\n", $2, $3, $4, $5);
	}

END	{ print "};" }
