/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/param.h>
#include <ctype.h>

#ifdef __EMX__
#include <strings.h>
#endif 

#include <bro_types.h>
#include <bro_hashtable.h>
#include <bro_debug.h>
#include <bro_config.h>

typedef enum {
  BRO_CONF_INT,
  BRO_CONF_DBL,
  BRO_CONF_STR,
  BRO_CONF_NET,
  BRO_CONF_ERR
} BroConfType;

typedef struct bro_conf_it
{
  char        *ci_name;
  BroConfType  ci_type;
  
  union {
    int             ci_int;
    double          ci_dbl;
    char           *ci_str;
  } ci_val;
  
#define ci_int ci_val.ci_int
#define ci_dbl ci_val.ci_dbl
#define ci_str ci_val.ci_str

} BroConfIt;


static char *config_file = BRO_SYSCONF_FILE;

/* The name of the current domain, may be NULL. */
static char  *cur_dom;

/* The default domain's configuration, used when cur_dom == NULL. */
static BroHT *default_conf;

/* While parsing the configuration, we switch from domain to domain
 * as contained in the file, but leave the user's currently selected
 * domain unaffected. We point to the current domain while parsing
 * using parsing_conf, which by default is the same as default_conf.
 */
static BroHT *parsing_conf;

/* A hashtable of hashtables, indexed by domain names. The inner
 * hash tables contain BroConfIt items, indexed by strings.
 */
static BroHT *dom_conf;

extern int __bro_parse_config(const char *filename);


static BroConfIt *
conf_item_new(const char *name, BroConfType type, void *val)
{
  BroConfIt *ci;

  if (! (ci = calloc(1, sizeof(BroConfIt))))
    return NULL;

  ci->ci_name = strdup(name);
  ci->ci_type = type;

  switch (type)
    {
    case BRO_CONF_INT:
      ci->ci_int = *((int*) val);
      break;

    case BRO_CONF_DBL:
      ci->ci_dbl = *((double*) val);
      break;

    case BRO_CONF_STR:
      ci->ci_str = strdup((char *) val);
      break;

    default:
      free(ci);
      return NULL;
    }

  return ci;
}

static void
conf_item_free(BroConfIt *ci)
{
  if (!ci)
    return;

  if (ci->ci_name)
    free(ci->ci_name);
  
  if (ci->ci_type == BRO_CONF_STR)
    {
      memset(ci->ci_str, 0, strlen(ci->ci_str));
      free(ci->ci_str);
      ci->ci_str = NULL;
    }
  
  free(ci);
}

static int
conf_permissions_ok(struct stat *st)
{
  /* We consider the file okay if it is not a link, only
   * the owner can read it, and the current user can open it.
   */
  if (S_ISREG(st->st_mode)      &&  /* regular file  */
      (st->st_mode & S_IRUSR)   &&  /* user-readable */
      ! (st->st_mode & S_IXUSR) &&  /* not user-exec'able (paranoia) */
      ! (st->st_mode & S_IRWXG) &&  /* no group permissions */
      ! (st->st_mode & S_IRWXO))    /* no other permissions */
    {
      if (st->st_uid == geteuid())
	return TRUE;
    }      
  
  fprintf(stderr, "Insufficient permissions for reading ~/.broccoli.conf.\n");
  fprintf(stderr, "NOTE: ~/.broccoli.conf must be regular file and -rw-------\n");
  return FALSE;
}

static char *
get_passwd_home(void)
{
#if defined(HAVE_GETEUID) && defined(HAVE_GETPWUID)
  struct passwd *passwd;
  uid_t uid = geteuid();

  if ( (passwd = getpwuid(uid)))
    {
      D(("Getting home directory from user %u's passwd entry: %s.\n", uid, passwd->pw_dir)); 
      return strdup(passwd->pw_dir);
    }
#endif

  return NULL;
}


void
__bro_conf_init(void)
{
  static int deja_vu = FALSE;
  struct stat st;    
  char *pwd_home = NULL;
  char home_config[MAXPATHLEN];
  char home_config2[MAXPATHLEN];
  int try_env = TRUE, debug_messages, debug_calltrace;

  if (deja_vu)
    return;

  home_config[0] = '\0';
  home_config2[0] = '\0';

  parsing_conf = default_conf = __bro_ht_new(__bro_ht_str_hash,
					     __bro_ht_str_cmp,
					     NULL,
					     (BroHTFreeFunc)conf_item_free,
					     FALSE);
  
  dom_conf = __bro_ht_new(__bro_ht_str_hash,
			  __bro_ht_str_cmp,
			  __bro_ht_mem_free,
			  (BroHTFreeFunc)__bro_ht_free,
			  FALSE);
  
  /* Now figure out what config file to read: if the user
   * has a ~/.broccoli.conf, use that, otherwise use the
   * global one. We first try via the passwd entry, then
   * fall back to using $HOME.
   */
  if ( (pwd_home = get_passwd_home()))
    {
      __bro_util_snprintf(home_config, MAXPATHLEN, "%s/.broccoli.conf", pwd_home);      
      free(pwd_home);

      if (stat(home_config, &st) == 0 && conf_permissions_ok(&st))
	{
	  config_file = strdup(home_config);
	  try_env = FALSE;
	}	
    }
  
  if (try_env)
    {
      __bro_util_snprintf(home_config2, MAXPATHLEN, "%s/.broccoli.conf", getenv("HOME"));
      
      /* Only check this variant if it didn't yield the same file as the
       * pwd-based filename.
       */
      if (strcmp(home_config, home_config2) &&
	  stat(home_config2, &st) == 0 && conf_permissions_ok(&st))
	config_file = strdup(home_config2);
    }
  
  __bro_parse_config(config_file);
  deja_vu = TRUE;

  /* Read out debugging verbosity settings and assign if found. */
  if (__bro_conf_get_int("/broccoli/debug_messages", &debug_messages))
    bro_debug_messages = debug_messages;
  if (__bro_conf_get_int("/broccoli/debug_calltrace", &debug_calltrace))
    bro_debug_calltrace = debug_calltrace;
  
}

static BroHT *
assert_domain(void)
{
  BroHT *conf = default_conf;

  D(("Selecting configuration domain, name is %s\n", cur_dom));

  if (cur_dom && ! (conf = (BroHT *)  __bro_ht_get(dom_conf, cur_dom)))
    {
      D(("Allocating domain '%s'\n", cur_dom));
      
      conf = __bro_ht_new(__bro_ht_str_hash,
			  __bro_ht_str_cmp,
			  NULL,
			  (BroHTFreeFunc)conf_item_free,
			  FALSE);
      
      __bro_ht_add(dom_conf, strdup(cur_dom), conf);
    }
  
  return conf;
}


void
__bro_conf_set_domain(const char *new_domain)
{
  /* First reset to the default domain */
  if (cur_dom)
    free(cur_dom);
  cur_dom = NULL;
  
  /* Then if given, switch to the new one. */
  if (new_domain && *new_domain)
    {
      char *str;

      str = cur_dom = strdup(new_domain);

      while (*str != '\0')
	{
	  *str = tolower(*str);
	  str++;
	}
      
      D(("Configuration domain set to '%s'\n", cur_dom));
    }
}


void
__bro_conf_set_storage_domain(const char *storage_domain)
{
  if (! storage_domain || ! *storage_domain)
    {
      parsing_conf = default_conf;
      return;
    }

  if (! (parsing_conf = (BroHT *)  __bro_ht_get(dom_conf, storage_domain)))
    {
      D(("Allocating domain '%s'\n", storage_domain));
      
      parsing_conf = __bro_ht_new(__bro_ht_str_hash,
				  __bro_ht_str_cmp,
				  NULL,
				  (BroHTFreeFunc)conf_item_free,
				  FALSE);
      
      __bro_ht_add(dom_conf, strdup(storage_domain), parsing_conf);
    }
}


const char   *
__bro_conf_get_domain(void)
{
  return cur_dom;
}


void
__bro_conf_add_int(const char *val_name, int val)
{
  BroConfIt *ci;

  if (! (ci = conf_item_new(val_name, BRO_CONF_INT, &val)))
    return;

  __bro_ht_add(parsing_conf, ci->ci_name, ci);
}


void
__bro_conf_add_dbl(const char *val_name, double val)
{
  BroConfIt *ci;

  if (! (ci = conf_item_new(val_name, BRO_CONF_DBL, &val)))
    return;

  __bro_ht_add(parsing_conf, ci->ci_name, ci);
}


void
__bro_conf_add_str(const char *val_name, char *val)
{
  BroConfIt *ci;

  if (! (ci = conf_item_new(val_name, BRO_CONF_STR, val)))
    return;

  __bro_ht_add(parsing_conf, ci->ci_name, ci);
}


int
__bro_conf_get_int(const char *val_name, int *val)
{
  BroConfIt *ci;
  BroHT *conf;

  __bro_conf_init();
  conf = assert_domain();

  do {
    if (! (ci = __bro_ht_get(conf, (void*) val_name)))
      break;    
    if (ci->ci_type != BRO_CONF_INT)
      break;

    *val = ci->ci_int;
    return TRUE;

  } while (0);

  do {
    if (! (ci = __bro_ht_get(default_conf, (void*) val_name)))
      break;   
    if (ci->ci_type != BRO_CONF_INT)
      break;

    *val = ci->ci_int;
    return TRUE;

  } while (0);

  return FALSE;
}


int
__bro_conf_get_dbl(const char *val_name, double *val)
{
  BroConfIt *ci;
  BroHT *conf;

  __bro_conf_init();
  conf = assert_domain();

  do {
    if (! (ci = __bro_ht_get(conf, (void*) val_name)))
      break;
    if (ci->ci_type != BRO_CONF_DBL)
      break;

    *val = ci->ci_dbl;
    return TRUE;
  } while (0);

  do {
    if (! (ci = __bro_ht_get(default_conf, (void*) val_name)))
      break;
    if (ci->ci_type != BRO_CONF_DBL)
      break;

    *val = ci->ci_dbl;
    return TRUE;
  } while (0);

  return FALSE;
}


const char *  
__bro_conf_get_str(const char *val_name)
{
  BroConfIt *ci;
  BroHT *conf;

  __bro_conf_init();
  conf = assert_domain();

  do {
    if (! (ci = __bro_ht_get(conf, (void*) val_name)))
      break;
    if (ci->ci_type != BRO_CONF_STR)
      break;
    
    return ci->ci_str;
  } while (0);

  do {
    if (! (ci = __bro_ht_get(default_conf, (void*) val_name)))
      break;
    if (ci->ci_type != BRO_CONF_STR)
      break;
    
    return ci->ci_str;
  } while (0);
  
  return NULL;
}


int
__bro_conf_forget_item(const char *val_name)
{
  BroConfIt *ci;
  BroHT *conf;

  __bro_conf_init();
  conf = assert_domain();

  if (! (ci = __bro_ht_del(conf, (void*) val_name)))
    {
      if (! (ci = __bro_ht_del(default_conf, (void*) val_name)))
	return FALSE;
    }

  conf_item_free(ci);
  return TRUE;
}

