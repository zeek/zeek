// See the file "COPYING" in the main distribution directory for copyright.

#include <string.h>
#include <limits.h>
#include <getopt.h>
// define required for FreeBSD
#define _WITH_GETLINE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* The maximum length of converted timestamp that zeek-cut can handle. */
#define MAX_TIMESTAMP_LEN 100

/* User-specified options that stay constant during a run of zeek-cut. */
struct useropts {
    int showhdr;     /* show log headers? (0=no, 1=only first, 2=all) */
    int minimalview; /* show headers in minimal view? (0=no, 1=yes) */
    int negate;      /* show all but the specified columns? (0=no, 1=yes) */
    int timeconv;    /* do time conversion? (0=no, 1=local, 2=UTC) */
    char **columns;  /* array of user-specified column names */
    int num_columns; /* number of user-specified column names */
    const char *ofs; /* user-specified output field separator character */
    const char *timefmt; /* strftime format string for time conversion */
};

/* Parameters that might change with each log file being processed. */
struct logparams {
    int *out_indexes;  /* array of log file column indices to output */
    int num_out_indexes;  /* number of elements in "out_indexes" */
    int idx_range;   /* max. value in "out_indexes" plus one */
    int *time_cols;  /* array of columns (0=not timestamp, 1=timestamp) */
    char **tmp_fields; /* array of pointers to each field on a line */
    int num_fields;    /* number of fields in log file */
    char ifs[2];     /* input field separator character */
    char ofs[2];     /* output field separator character */
    char *unsetf;    /* unset field string */
    long prev_ts;    /* previous timestamp */
};


int usage(void) {
    puts("\nzeek-cut [options] [<columns>]\n");
    puts("Extracts the given columns from ASCII Zeek logs on standard input, and outputs");
    puts("them to standard output. If no columns are given, all are selected.");
    puts("By default, zeek-cut does not include format header blocks in the output.");
    puts("\nExample: cat conn.log | zeek-cut -d ts id.orig_h id.orig_p");
    puts("\n    -c       Include the first format header block in the output.");
    puts("    -C       Include all format header blocks in the output.");
    puts("    -m       Include the first format header blocks in the output in minimal view.");
    puts("    -M       Include all format header blocks in the output in minimal view.");
    puts("    -d       Convert time values into human-readable format.");
    puts("    -D <fmt> Like -d, but specify format for time (see strftime(3) for syntax).");
    puts("    -F <ofs> Sets a different output field separator character.");
    puts("    -h       Show help.");
    puts("    -n       Print all fields *except* those specified.");
    puts("    -u       Like -d, but print timestamps in UTC instead of local time.");
    puts("    -U <fmt> Like -D, but print timestamps in UTC instead of local time.\n");
    puts("For time conversion option -d or -u, the format string can be specified by");
    puts("setting an environment variable ZEEK_CUT_TIMEFMT.\n");
    exit(1);
}

/* Return the index in "haystack" where "needle" is located (or -1 if not
 * found).
 */
int string_index(char *haystack[], int haystack_size, const char *needle) {
    int i;
    for (i = 0; i < haystack_size; ++i) {
        if (!strcmp(haystack[i], needle)) {
            return i;
        }
    }
    return -1;
}

/* Return the input field separator from the log's "#separator " header line. */
char parsesep(const char *sepstr) {
    char ifs;

    if (!strncmp(sepstr, "\\x", 2)) {
        long sepval = strtol(sepstr + 2, NULL, 16);
        ifs = sepval;
    } else {
        ifs = sepstr[0];
    }

    return ifs;
}

/* Determine the columns (if any) where the field is "time".  Return 0 for
 * success, and non-zero otherwise.
 */
int find_timecol(const char *line, struct logparams *lp) {
    int i;
    int *tmpptr;
    char *copy_of_line;
    char *field_ptr;
    char *field;

    tmpptr = (int *) realloc(lp->time_cols, lp->idx_range * sizeof(int));
    if (tmpptr == NULL) {
        fputs("zeek-cut: out of memory\n", stderr);
        return 1;
    }

    lp->time_cols = tmpptr;

    if ((copy_of_line = strdup(line)) == NULL) {
        fputs("zeek-cut: out of memory\n", stderr);
        return 1;
    }
    field_ptr = copy_of_line;

    int ret = 0;
    for (i = 0; i < lp->idx_range; ++i) {
        if ((field = strsep(&field_ptr, lp->ifs)) == NULL) {
            fputs("zeek-cut: log header does not have enough fields\n", stderr);
            ret = 1;
            break;
        }

        /* Set value of 1 for each "time" column, or 0 otherwise */
        lp->time_cols[i] = strcmp("time", field) ? 0 : 1;
    }

    free(copy_of_line);
    return ret;
}

/* Allocate memory for "out_indexes" and store index numbers there
 * corresponding to the columns in "line" that we want to output later.
 * Set the number of elements in "out_indexes".  Also
 * store in "idx_range" the maximum value contained in "out_indexes" plus one.
 * Return 0 for success, and non-zero otherwise.
 */
int find_output_indexes(char *line, struct logparams *lp, struct useropts *bopts) {
    int idx;
    int *out_indexes;
    char *field_ptr;
    char *copy_of_line = NULL;
    char *field;

    /* Get the number of fields */
    lp->num_fields = 0;
    field = line;
    while ((field = strchr(field, lp->ifs[0])) != NULL) {
        lp->num_fields++;
        field++;
    }
    lp->num_fields++;

    char **tmpptr;
    /* note: size is num_fields+1 because header lines have an extra field */
    tmpptr = (char **) realloc(lp->tmp_fields, (lp->num_fields + 1) * sizeof(char *));
    if (tmpptr == NULL) {
        return 1;
    }
    lp->tmp_fields = tmpptr;

    if (bopts->num_columns == 0) {
        /* No columns specified on cmd-line, so use all the columns */
        out_indexes = (int *) realloc(lp->out_indexes, lp->num_fields * sizeof(int));
        if (out_indexes == NULL) {
            return 1;
        }

        for (idx = 0; idx < lp->num_fields; ++idx) {
            out_indexes[idx] = idx;
        }

        lp->out_indexes = out_indexes;
        lp->idx_range = lp->num_fields;
        lp->num_out_indexes = lp->num_fields;
        return 0;
    }

    /* Set tmp_fields to point to each field on the line */
    if ((copy_of_line = strdup(line)) == NULL) {
        return 1;
    }
    field_ptr = copy_of_line;

    idx = 0;
    while ((field = strsep(&field_ptr, lp->ifs)) != NULL) {
        lp->tmp_fields[idx++] = field;
    }

    int out_idx = 0;
    int maxval = 0;

    if (!bopts->negate) {
        /* One or more column names were specified on cmd-line */
        out_indexes = (int *) realloc(lp->out_indexes, bopts->num_columns * sizeof(int));
        if (out_indexes == NULL) {
            return 1;
        }

        for (idx = 0; idx < bopts->num_columns; ++idx) {
            out_indexes[idx] = string_index(lp->tmp_fields, lp->num_fields, bopts->columns[idx]);
            if (out_indexes[idx] > maxval) {
                maxval = out_indexes[idx];
            }
        }
        out_idx = bopts->num_columns;
    } else {
        /* The "-n" option was specified on cmd-line */
        out_indexes = (int *) realloc(lp->out_indexes, lp->num_fields * sizeof(int));
        if (out_indexes == NULL) {
            return 1;
        }

        for (idx = 0; idx < lp->num_fields; ++idx) {
            if (string_index(bopts->columns, bopts->num_columns, lp->tmp_fields[idx]) == -1) {
                out_indexes[out_idx++] = idx;
                if (idx > maxval) {
                    maxval = idx;
                }
            }
        }
    }

    free(copy_of_line);

    lp->out_indexes = out_indexes;
    lp->idx_range = maxval + 1;
    lp->num_out_indexes = out_idx;
    return 0;
}

/*
 * Try to convert a time value to a human-readable timestamp, and then output
 * the result.  A valid time value is one or more digits followed by a decimal
 * point (everything after the decimal point is ignored).  If the time
 * conversion fails for any reason, then just output the field unmodified.
 */
void output_time(const char *field, struct logparams *lp, struct useropts *bopts) {
    /* Buffer is declared static in order to reuse the timestamp string */
    static char tbuf[MAX_TIMESTAMP_LEN];

    char *tmp;
    long tl = strtol(field, &tmp, 10);

    if (tl < 0 || tl == LONG_MAX) {
        fprintf(stderr, "zeek-cut: time value out-of-range: %s\n", field);
    } else if (*tmp != '.') {
        if (strcmp(field, lp->unsetf)) {
            /* field is not a valid value and is not the unset field string */
            fprintf(stderr, "zeek-cut: time field is not valid: %s\n", field);
        }
    } else if (tl == lp->prev_ts) {
        /* timestamp is same as the previous one, so skip the conversion */
        fputs(tbuf, stdout);
        return;
    } else {
        time_t tt = tl;
        struct tm tmval;
        struct tm* tmptr;
        tmptr = bopts->timeconv == 1 ? localtime_r(&tt, &tmval) : gmtime_r(&tt, &tmval);

        if (tmptr) {
            if (strftime(tbuf, sizeof(tbuf), bopts->timefmt, tmptr)) {
                /* output the formatted timestamp */
                fputs(tbuf, stdout);
                lp->prev_ts = tl;
                return;
            } else {
                fputs("zeek-cut: failed to convert timestamp (try a shorter format string)\n", stderr);
            }
        } else {
            /* the time conversion will fail for large values */
            fprintf(stderr, "zeek-cut: time value out-of-range: %s\n", field);
        }
    }

    /* failed to convert, so just output the field without modification */
    fputs(field, stdout);
}

/* Output the columns of "line" that the user specified.  The value of "hdr"
 * indicates whether "line" is a header line or not (0=not header, 1=header).
 */
void output_indexes(int hdr, char *line, struct logparams *lp, struct useropts *bopts) {
    int i;
    char *field;
    int dotimeconv = 0;  /* do a time conversion on this line? (0=no, 1=yes) */
    int dotimetypeconv = 0; /* change time type on this line? (0=no, 1=yes) */
    int idxrange = lp->idx_range + hdr; /* header lines have one extra field */
    int firstdone = 0;

    /* If user selected time conversion and this line is not a header line,
     * then try to do a time conversion.
     */
    if (bopts->timeconv && !hdr) {
        dotimeconv = 1;
    }

    for (i = 0; i < idxrange; ++i) {
        if ((field = strsep(&line, lp->ifs)) == NULL) {
            fputs("zeek-cut: skipping log line (not enough fields)\n", stderr);
            return;
        }
        lp->tmp_fields[i] = field;
    }

    /* If user selected time conversion and this line is a "#types" header,
     * then try to change the "time" type field.
     */
    if (bopts->timeconv && hdr && !strcmp(lp->tmp_fields[0], "#types")) {
        dotimetypeconv = 1;
    }

    if (hdr && bopts->minimalview == 0) {
        /* Output the initial "#" field on the header line */
        fputs(lp->tmp_fields[0], stdout);
        firstdone = 1;
    }

    for (i = 0; i < lp->num_out_indexes; ++i) {
        int idxval = lp->out_indexes[i];

        if (firstdone)
            fputs(lp->ofs, stdout);

        if (idxval != -1) {
            if (dotimeconv && lp->time_cols[idxval]) {
                /* output time field */
                output_time(lp->tmp_fields[idxval], lp, bopts);
            } else if (dotimetypeconv && !strcmp("time", lp->tmp_fields[idxval + hdr])) {
                /* change the "time" type field to "string" */
                fputs("string", stdout);
            } else {
                /* output the field without modification */
                fputs(lp->tmp_fields[idxval + hdr], stdout);
            }

        }

        /* Note: even when idxval == -1, we still need to set "firstdone" so
         * that a separator is output.
         */
        firstdone = 1;
    }
    putchar('\n');
}

/* Reads one or more log files from stdin and outputs them to stdout according
 * to the options specified in "bopts".  Returns 0 on success, and non-zero
 * otherwise.
 */
int zeek_cut(struct useropts bopts) {
    int ret = 0;
    struct logparams lp;   /* parameters specific to each log file */
    int headers_seen = 0;  /* 0=no header blocks seen, 1=one seen, 2=2+ seen */
    int prev_line_hdr = 0; /* previous line was a header line? 0=no, 1=yes */
    int prev_fields_line = 0; /* previous line was #fields line? 0=no, 1=yes */
    ssize_t linelen;
    size_t linesize = 100000;
    char *line = (char *) malloc(linesize);

    if (line == NULL) {
        fputs("zeek-cut: out of memory\n", stderr);
        return 1;
    }

    lp.out_indexes = NULL;
    lp.num_out_indexes = 0;
    lp.idx_range = 0;
    lp.time_cols = NULL;
    lp.tmp_fields = NULL;
    lp.num_fields = 0;
    lp.ofs[0] = '\t';
    lp.ofs[1] = '\0';
    lp.ifs[0] = '\t';
    lp.ifs[1] = '\0';
    lp.unsetf = strdup("-");
    lp.prev_ts = -1; /* initialize with an invalid time value */

    if (lp.unsetf == NULL) {
        fputs("zeek-cut: out of memory\n", stderr);
        free(line);
        return 1;
    }

    while ((linelen = getline(&line, &linesize, stdin)) > 0) {
        /* Remove trailing '\n' */
        line[linelen - 1] = '\0';

        if (prev_fields_line && strncmp(line, "#types", 6)) {
            fputs("zeek-cut: bad log header (missing #types line)\n", stderr);
            ret = 1;
            break;
        }

        /* Check if this line is a header line or not */
        if (line[0] != '#') {
            prev_line_hdr = 0;
            output_indexes(0, line, &lp, &bopts);
            continue;
        }

        /* The rest of this loop is for header processing */

        if (!prev_line_hdr) {
            /* Here we are transitioning from non-header to header line */
            prev_line_hdr = 1;
            /* Once we've seen two header blocks, we stop counting them */
            if (headers_seen < 2) {
                headers_seen++;
            }
        }

        if (!strncmp(line, "#separator ", 11)) {
            char ifs = parsesep(line + 11);
            if (ifs == '\0') {
                fputs("zeek-cut: bad log header (invalid #separator line)\n", stderr);
                ret = 1;
                break;
            }

            lp.ifs[0] = ifs;

            /* If user-specified ofs is set, then use it. Otherwise, just
             * use the log file's input field separator.
             */
            lp.ofs[0] = bopts.ofs[0] ? bopts.ofs[0] : lp.ifs[0];
        } else if (!strncmp(line, "#unset_field", 12)) {
            if (line[12] && line[13]) {
                free(lp.unsetf);
                if ((lp.unsetf = strdup(line + 13)) == NULL) {
                    fputs("zeek-cut: out of memory\n", stderr);
                    ret = 1;
                    break;
                }
            } else {
                fputs("zeek-cut: bad log header (invalid #unset_field line)\n", stderr);
                ret = 1;
                break;
            }
        } else if (!strncmp(line, "#fields", 7)) {
            prev_fields_line = 1;
            if (find_output_indexes(line + 8, &lp, &bopts)) {
                fputs("zeek-cut: out of memory\n", stderr);
                ret = 1;
                break;
            }
        } else if (!strncmp(line, "#types", 6)) {
            if (!prev_fields_line) {
                fputs("zeek-cut: bad log header (missing #fields line)\n", stderr);
                ret = 1;
                break;
            }
            prev_fields_line = 0;

            if (bopts.timeconv) {
                if (find_timecol(line + 7, &lp)) {
                    ret = 1;
                    break;
                }
            }
        }

        /* Decide if we want to output this header */
        if (bopts.showhdr >= headers_seen) {
            if (!strncmp(line, "#fields", 7) || (!strncmp(line, "#types", 6) && (bopts.minimalview == 0))) {
                /* Output a modified "#fields" or "#types" header line */
                output_indexes(1, line, &lp, &bopts);
            } else if (bopts.minimalview == 0) {
                /* Output the header line with no changes */
                puts(line);
            }
        }

    }

    free(lp.time_cols);
    free(lp.out_indexes);
    free(lp.tmp_fields);
    free(lp.unsetf);
    free(line);
    return ret;
}

int main(int argc, char *argv[]) {
    int c;
    char *envtimefmt = getenv("ZEEK_CUT_TIMEFMT");
    if (envtimefmt == NULL) {
        envtimefmt = getenv("BRO_CUT_TIMEFMT");
        if (envtimefmt != NULL)
            fprintf(stderr, "zeek-cut warning: using legacy environment variable BRO_CUT_TIMEFMT, set ZEEK_CUT_TIMEFMT instead\n");
    }

    struct useropts bopts;
    bopts.showhdr = 0;
    bopts.minimalview = 0;
    bopts.negate = 0;
    bopts.timeconv = 0;
    bopts.ofs = "";
    bopts.timefmt = envtimefmt ? envtimefmt : "%Y-%m-%dT%H:%M:%S%z";

    static struct option long_opts[] = {
        {"help",    no_argument,    0,  'h'},
        {0,         0,              0,  0}
    };

    while ((c = getopt_long(argc, argv, "cCmMnF:duD:U:h", long_opts, NULL)) != -1) {
        switch (c) {
            case 'c':
                bopts.minimalview = 0;
                bopts.showhdr = 1;
                break;
            case 'C':
                bopts.minimalview = 0;
                bopts.showhdr = 2;
                break;
            case 'm':
                bopts.minimalview = 1;
                bopts.showhdr = 1;
                break;
            case 'M':
                bopts.minimalview = 1;
                bopts.showhdr = 2;
                break;
            case 'n':
                bopts.negate = 1;
                break;
            case 'F':
                if (strlen(optarg) != 1) {
                    fputs("zeek-cut: field separator must be a single character\n", stderr);
                    exit(1);
                }
                bopts.ofs = optarg;
                break;
            case 'd':
                bopts.timeconv = 1;
                break;
            case 'u':
                bopts.timeconv = 2;
                break;
            case 'D':
                bopts.timeconv = 1;
                bopts.timefmt = optarg;
                break;
            case 'U':
                bopts.timeconv = 2;
                bopts.timefmt = optarg;
                break;
            default:
                usage();
                break;
        }
    }

    if (bopts.timeconv && strlen(bopts.timefmt) == 0) {
        fputs("zeek-cut: time format string cannot be empty\n", stderr);
        exit(1);
    }

    bopts.columns = &argv[optind];
    bopts.num_columns = argc - optind;

    return zeek_cut(bopts);
}
