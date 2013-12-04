/*
  Taken with permission from:

  p0f - passive OS fingerprinting (GNU LESSER GENERAL PUBLIC LICENSE)
  -------------------------------------------------------------------

  "If you sit down at a poker game and don't see a sucker,
  get up. You're the sucker."

  (C) Copyright 2000-2003 by Michal Zalewski <lcamtuf@coredump.cx>
*/

// To make it easier to upgrade this file to newer releases of p0f,
// it remains in the coding style used by p0f rather than Bro.

#include "OSFinger.h"
#include "net_util.h"
#include "util.h"
#include "Var.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>


void int_delete_func(void* v)
	{
	delete (int*) v;
	}


// Initializes data structures for fingerprinting in the given mode.
OSFingerprint::OSFingerprint(FingerprintMode arg_mode)
  {
  err = 0;
  mode = arg_mode;

  sigcnt=gencnt=0;
  problems=0;
  char* fname;

  memset(sig, 0, sizeof(struct fp_entry)*MAXSIGS);
  memset(bh, 0, sizeof(struct fp_entry*)*OSHSIZE);

  os_matches.SetDeleteFunc(int_delete_func);

  if (mode == SYN_FINGERPRINT_MODE)
    {
    fname = copy_string(internal_val("passive_fingerprint_file")->AsString()->CheckString());
    load_config(fname);
    delete [] fname;
    }
  else if (mode == SYN_ACK_FINGERPRINT_MODE)
    {//not yet supported
    load_config("p0fsynack.sig");
    }
  else if (mode == RST_FINGERPRINT_MODE)
    {//not yet supported
    load_config("p0frst.sig");
    }
  else
    {
    Error("OS fingerprinting: unknown mode!");
    }
}

bool OSFingerprint::CacheMatch(const IPAddr& addr, int id)
  {
  HashKey* key = addr.GetHashKey();
  int* pid = new int;
  *pid=id;
  int* prev = os_matches.Insert(key, pid);
  bool ret = (prev ? *prev != id : 1);
  if (prev)
    delete prev;
  delete key;
  return ret;
  }


// Determines whether the signature file had any collisions.
void OSFingerprint::collide(uint32 id)
  {
  uint32 i,j;
  uint32 cur;

  if (sig[id].ttl % 32 && sig[id].ttl != 255 && sig[id].ttl % 30)
    {
    problems=1;
    reporter->Warning("OS fingerprinting: [!] Unusual TTL (%d) for signature '%s %s' (line %d).",
          sig[id].ttl,sig[id].os,sig[id].desc,sig[id].line);
    }

  for (i=0;i<id;i++)
    {
    if (!strcmp(sig[i].os,sig[id].os) &&
        !strcmp(sig[i].desc,sig[id].desc)) {
      problems=1;
      reporter->Warning("OS fingerprinting: [!] Duplicate signature name: '%s %s' (line %d and %d).",
            sig[i].os,sig[i].desc,sig[i].line,sig[id].line);
    }

    /* If TTLs are sufficiently away from each other, the risk of
       a collision is lower. */
    if (abs((int)sig[id].ttl - (int)sig[i].ttl) > 25) continue;

    if (sig[id].df ^ sig[i].df) continue;
    if (sig[id].zero_stamp ^ sig[i].zero_stamp) continue;

    /* Zero means >= PACKET_BIG */
    if (sig[id].size) { if (sig[id].size ^ sig[i].size) continue; }
      else if (sig[i].size < PACKET_BIG) continue;

    if (sig[id].optcnt ^ sig[i].optcnt) continue;
    if (sig[id].quirks ^ sig[i].quirks) continue;

    switch (sig[id].wsize_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsize;

do_const:

        switch (sig[i].wsize_mod) {

          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsize) continue;
            break;

          case MOD_CONST: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsize) continue;
            break;

          case MOD_MSS: /* Current: const, prev: mod MSS */

            if (sig[i].mss_mod || sig[i].wsize *
	       (sig[i].mss ? sig[i].mss : 1460 ) != (int) cur)
              continue;

            break;

          case MOD_MTU: /* Current: const, prev: mod MTU */

            if (sig[i].mss_mod || sig[i].wsize * (
	        (sig[i].mss ? sig[i].mss : 1460 )+40) != (int) cur)
              continue;

            break;

        }

        break;

      case 1: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the
           previous modulo */

        if (sig[i].wsize_mod != MOD_CONST) continue;
        if (sig[id].wsize % sig[i].wsize) continue;

        break;

      case MOD_MSS: /* Current is modulo MSS */

        /* There's likely a problem only if the previous one is close
           to '*'; we do not check known MTUs, because this particular
           signature can be made with some uncommon MTUs in mind. The
           problem would also appear if current signature has a fixed
           MSS. */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize >= 8) {
          if (!sig[id].mss_mod) {
            cur = (sig[id].mss ? sig[id].mss : 1460 ) * sig[id].wsize;
            goto do_const;
          }
          continue;
        }

        break;

      case MOD_MTU: /* Current is modulo MTU */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize <= 8) {
          if (!sig[id].mss_mod) {
            cur = ( (sig[id].mss ? sig[id].mss : 1460 ) +40) * sig[id].wsize;
            goto do_const;
          }
          continue;
        }

        break;

    }

    /* Same for wsc */
    switch (sig[id].wsc_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsc;

        switch (sig[i].wsc_mod) {

          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsc) continue;
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsc) continue;
            break;

        }

        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the
           previous modulo */

        if (!sig[i].wsc_mod) continue;
        if (sig[id].wsc % sig[i].wsc) continue;

        break;

     }

    /* Same for mss */
    switch (sig[id].mss_mod) {

      case 0: /* Current: const */

        cur=sig[id].mss;

        switch (sig[i].mss_mod) {

          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].mss) continue;
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].mss) continue;
            break;

        }

        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the
           previous modulo */

        if (!sig[i].mss_mod) continue;
        if ((sig[id].mss ? sig[id].mss : 1460 ) %
	    (sig[i].mss ? sig[i].mss : 1460 )) continue;

        break;

     }

     /* Now check option sequence */

    for (j=0;j<sig[id].optcnt;j++)
      if (sig[id].opt[j] ^ sig[i].opt[j]) goto reloop;

    problems=1;
    reporter->Warning("OS fingerprinting: [!] Signature '%s %s' (line %d)\n"
          "    is already covered by '%s %s' (line %d).",
          sig[id].os,sig[id].desc,sig[id].line,sig[i].os,sig[i].desc,
          sig[i].line);

reloop:
    ;
    }
  }

// Loads a given file into to classes data structures.
void OSFingerprint::load_config(const char* file)
  {
  uint32 ln=0;
  char buf[MAXLINE];
  char* p;

  FILE* c = open_file(find_file(file, bro_path(), "osf"));

  if (!c)
    {
    Error("Can't open OS passive fingerprinting signature file", file);
    return;
    }
  sigcnt=0; //every time we read config we reset it to 0;
  while ((p=fgets(buf,sizeof(buf),c)))
    {
    uint32 l;

    char obuf[MAXLINE],genre[MAXLINE],desc[MAXLINE],quirks[MAXLINE];
    char w[MAXLINE],sb[MAXLINE];
    char* gptr = genre;
    uint32 t,d,s;
    struct fp_entry* e;

    ln++;

    /* Remove leading and trailing blanks */
    while (isspace(*p)) p++;
    l=strlen(p);
    while (l && isspace(*(p+l-1))) *(p+(l--)-1)=0;
	
    /* Skip empty lines and comments */
    if (!l) continue;
    if (*p == '#') continue;

    if (sscanf(p,"%[0-9%*()ST]:%d:%d:%[0-9()*]:%[^:]:%[^ :]:%[^:]:%[^:]",
                  w,         &t,&d,sb,     obuf, quirks,genre,desc) != 8)
      Error("OS fingerprinting: Syntax error in p0f signature config line %d.\n",(uint32)ln);

    gptr = genre;

    if (*sb != '*') s = atoi(sb); else s = 0;

reparse_ptr:

    switch (*gptr)
      {
      case '-': sig[sigcnt].userland = 1; gptr++; goto reparse_ptr;
      case '*': sig[sigcnt].no_detail = 1; gptr++; goto reparse_ptr;
      case '@': sig[sigcnt].generic = 1; gptr++; gencnt++; goto reparse_ptr;
      case 0: Error("OS fingerprinting: Empty OS genre in line",(uint32)ln);
      }

    sig[sigcnt].os     = strdup(gptr);
    sig[sigcnt].desc   = strdup(desc);
    sig[sigcnt].ttl    = t;
    sig[sigcnt].size   = s;
    sig[sigcnt].df     = d;
 
    if (w[0] == '*')
      {
      sig[sigcnt].wsize = 1;
      sig[sigcnt].wsize_mod = MOD_CONST;
      }
    else if (tolower(w[0]) == 's')
      {
      sig[sigcnt].wsize_mod = MOD_MSS;
      if (!isdigit(*(w+1)))
	Error("OS fingerprinting: Bad Snn value in WSS in line",(uint32)ln);
      sig[sigcnt].wsize = atoi(w+1);
      }
    else if (tolower(w[0]) == 't')
      {
      sig[sigcnt].wsize_mod = MOD_MTU;
      if (!isdigit(*(w+1)))
	Error("OS fingerprinting: Bad Tnn value in WSS in line",(uint32)ln);
      sig[sigcnt].wsize = atoi(w+1);
      }
    else if (w[0] == '%')
      {
      if (!(sig[sigcnt].wsize = atoi(w+1)))
        Error("OS fingerprinting: Null modulo for window size in config line",(uint32)ln);
      sig[sigcnt].wsize_mod = MOD_CONST;
      }
    else
      sig[sigcnt].wsize = atoi(w);

    /* Now let's parse options */

    p=obuf;

    sig[sigcnt].zero_stamp = 1;

    if (*p=='.') p++;

    while (*p)
      {
      uint8 optcnt = sig[sigcnt].optcnt;
      switch (tolower(*p))
	{
        case 'n': sig[sigcnt].opt[optcnt] = TCPOPT_NOP;
                  break;

        case 'e': sig[sigcnt].opt[optcnt] = TCPOPT_EOL;
                  if (*(p+1))
                    Error("OS fingerprinting: EOL not the last option, line",(uint32)ln);
                  break;

        case 's': sig[sigcnt].opt[optcnt] = TCPOPT_SACK_PERMITTED;
                  break;

        case 't': sig[sigcnt].opt[optcnt] = TCPOPT_TIMESTAMP;
                  if (*(p+1)!='0')
		    {
                    sig[sigcnt].zero_stamp=0;
                    if (isdigit(*(p+1)))
                      Error("OS fingerprinting: Bogus Tstamp specification in line",(uint32)ln);
		    }
                  break;

        case 'w': sig[sigcnt].opt[optcnt] = TCPOPT_WINDOW;
                  if (p[1] == '*')
		    {
                    sig[sigcnt].wsc = 1;
                    sig[sigcnt].wsc_mod = MOD_CONST;
		    }
		  else if (p[1] == '%')
		    {
                    if (!(sig[sigcnt].wsc = atoi(p+2)))
                      Error("OS fingerprinting: Null modulo for wscale in config line",(uint32)ln);
                    sig[sigcnt].wsc_mod = MOD_CONST;
		    }
		  else if (!isdigit(*(p+1)))
                    Error("OS fingerprinting: Incorrect W value in line",(uint32)ln);
                  else sig[sigcnt].wsc = atoi(p+1);
                  break;

        case 'm': sig[sigcnt].opt[optcnt] = TCPOPT_MAXSEG;
                  if (p[1] == '*')
		    {
                    sig[sigcnt].mss = 1;
                    sig[sigcnt].mss_mod = MOD_CONST;
		    }
		  else if (p[1] == '%')
		    {
                    if (!(sig[sigcnt].mss = atoi(p+2)))
                      Error("OS fingerprinting: Null modulo for MSS in config line",(uint32)ln);
                    sig[sigcnt].mss_mod = MOD_CONST;
		    }
		  else if (!isdigit(*(p+1)))
                    Error("OS fingerprinting: Incorrect M value in line",(uint32)ln);
                  else sig[sigcnt].mss = atoi(p+1);
                  break;

        /* Yuck! */
        case '?': if (!isdigit(*(p+1)))
                    Error("OS fingerprinting: Bogus ?nn value in line",(uint32)ln);
                  else sig[sigcnt].opt[optcnt] = atoi(p+1);
                  break;

        default: Error("OS fingerprinting: Unknown TCP option in config line",(uint32)ln);
	}

      if (++sig[sigcnt].optcnt >= MAXOPT)
        Error("OS fingerprinting: Too many TCP options specified in config line",(uint32)ln);

      /* Skip separators */
      do { p++; } while (*p && !isalpha(*p) && *p != '?');

    }
 
    sig[sigcnt].line = ln;

    p = quirks;

    while (*p)
      switch (toupper(*(p++)))
	{
        case 'E':
          Error("OS fingerprinting: Quirk 'E' is obsolete. Remove it, append E to the options. Line",(uint32)ln);

        case 'K':
	  if ( mode != RST_FINGERPRINT_MODE )
	    Error("OS fingerprinting: Quirk 'K' is valid only in RST+ (-R) mode (wrong config file?). Line",(uint32)ln);
  	  sig[sigcnt].quirks |= QUIRK_RSTACK;
	  break;

        case 'Q': sig[sigcnt].quirks |= QUIRK_SEQEQ; break;
        case '0': sig[sigcnt].quirks |= QUIRK_SEQ0; break;
        case 'P': sig[sigcnt].quirks |= QUIRK_PAST; break;
        case 'Z': sig[sigcnt].quirks |= QUIRK_ZEROID; break;
        case 'I': sig[sigcnt].quirks |= QUIRK_IPOPT; break;
        case 'U': sig[sigcnt].quirks |= QUIRK_URG; break;
        case 'X': sig[sigcnt].quirks |= QUIRK_X2; break;
        case 'A': sig[sigcnt].quirks |= QUIRK_ACK; break;
        case 'T': sig[sigcnt].quirks |= QUIRK_T2; break;
        case 'F': sig[sigcnt].quirks |= QUIRK_FLAGS; break;
        case 'D': sig[sigcnt].quirks |= QUIRK_DATA; break;
        case '!': sig[sigcnt].quirks |= QUIRK_BROKEN; break;
        case '.': break;
        default: Error("OS fingerprinting: Bad quirk in line",(uint32)ln);
	}

    e = bh[SIGHASH(s,sig[sigcnt].optcnt,sig[sigcnt].quirks,d)];

    if (!e)
      {
      bh[SIGHASH(s,sig[sigcnt].optcnt,sig[sigcnt].quirks,d)] = &sig[sigcnt];
      }
    else
      {
      while (e->next) e = e->next;
      e->next = &sig[sigcnt];
      }

    collide(sigcnt);
    if (++sigcnt >= MAXSIGS)
      Error("OS fingerprinting: Maximum signature count exceeded.\n");

    }

  fclose(c);

  if (!sigcnt)
    Error("OS fingerprinting: no signatures loaded from config file.");

  }

// Does the actual match between the packet and the signature database.
// Modifies retval and contains OS Type and other useful information.
// Returns config-file line of the matching signature as id.
int OSFingerprint::FindMatch(struct os_type* retval, uint16 tot,uint8 df,
			      uint8 ttl,uint16 wss,uint8 ocnt,uint8* op,
			      uint16 mss,uint8 wsc,uint32 tstamp,
			      uint32 quirks,uint8 ecn) const
  {
  uint32 j; //used for counter in loops
  struct fp_entry* p;
  uint8  orig_df  = df;

  struct fp_entry* fuzzy = 0;
  uint8 fuzzy_now = 0;
  int id = 0; //return value: 0 indicates no match.

  retval->os="UNKNOWN";
  retval->desc=NULL;
  retval->gadgets=0;
  retval->match=0;
  retval->uptime=0;

re_lookup:

  p = bh[SIGHASH(tot,ocnt,quirks,df)];

  while (p)
    {
    /* Cheap and specific checks first... */
    /* psize set to zero means >= PACKET_BIG */
    if (p->size) { if (tot ^ p->size) { p = p->next; continue; } }
      else if (tot < PACKET_BIG) { p = p->next; continue; }

    if (ocnt ^ p->optcnt) { p = p->next; continue; }

    if (p->zero_stamp ^ (!tstamp)) { p = p->next; continue; }
    if (p->df ^ df) { p = p->next; continue; }
    if (p->quirks ^ quirks) { p = p->next; continue; }

    /* Check MSS and WSCALE... */
    if (!p->mss_mod) {
      if (mss ^ p->mss) { p = p->next; continue; }
    } else if (mss % p->mss) { p = p->next; continue; }

    if (!p->wsc_mod) {
      if (wsc ^ p->wsc) { p = p->next; continue; }
    } else if (wsc % p->wsc) { p = p->next; continue; }

    /* Then proceed with the most complex WSS check... */
    switch (p->wsize_mod)
      {
      case 0:
        if (wss ^ p->wsize) { p = p->next; continue; }
        break;
      case MOD_CONST:
        if (wss % p->wsize) { p = p->next; continue; }
        break;
      case MOD_MSS:
        if (mss && !(wss % mss))
	  {
          if ((wss / mss) ^ p->wsize) { p = p->next; continue; }
	  }
	else if (!(wss % 1460))
	  {
          if ((wss / 1460) ^ p->wsize) { p = p->next; continue; }
	  }
	else { p = p->next; continue; }
        break;
      case MOD_MTU:
        if (mss && !(wss % (mss+40)))
	  {
          if ((wss / (mss+40)) ^ p->wsize) { p = p->next; continue; }
	  }
	else if (!(wss % 1500))
	  {
          if ((wss / 1500) ^ p->wsize) { p = p->next; continue; }
	  }
	else { p = p->next; continue; }
        break;
      }

    /* Numbers agree. Let's check options */
    for (j=0;j<ocnt;j++)
      if (p->opt[j] ^ op[j]) goto continue_search;

    /* Check TTLs last because we might want to go fuzzy. */
    if (p->ttl < ttl)
      {
      if ( mode != RST_FINGERPRINT_MODE )fuzzy = p;
      p = p->next;
      continue;
      }

    /* Naah... can't happen ;-) */
    if (!p->no_detail)
      if (p->ttl - ttl > MAXDIST)
	{
        if (mode != RST_FINGERPRINT_MODE ) fuzzy = p;
        p = p->next;
        continue;
	}

continue_fuzzy:

    /* Match! */
    id = p->line;
    if (mss & wss)
      {
      if (p->wsize_mod == MOD_MSS)
	{
        if ((wss % mss) && !(wss % 1460)) retval->gadgets|=GADGETNAT;
	}
      else if (p->wsize_mod == MOD_MTU)
	{
        if ((wss % (mss+40)) && !(wss % 1500)) retval->gadgets|=GADGETNAT2;
	}
      }

    retval->os=p->os;
    retval->desc=p->desc;
    retval->dist=p->ttl-ttl;

    if (ecn) retval->gadgets|=GADGETECN;
    if (orig_df ^ df) retval->gadgets|=GADGETFIREWALL;

    if (p->generic) retval->match=MATCHGENERIC;
    if (fuzzy_now) retval->match=MATCHFUZZY;

    if (!p->no_detail && tstamp)
      {
      retval->uptime=tstamp/360000;
      retval->gadgets|=GADGETUPTIME;
      }

    return id;

continue_search:

    p = p->next;

    }

  if (!df) { df = 1; goto re_lookup; } //not found with df=0 do df=1

  if (fuzzy)
    {
    df = orig_df;
    fuzzy_now = 1;
    p = fuzzy;
    fuzzy = 0;
    goto continue_fuzzy;
    }

  if (mss & wss)
    {
    if ((wss % mss) && !(wss % 1460)) retval->gadgets|=GADGETNAT;
    else if ((wss % (mss+40)) && !(wss % 1500)) retval->gadgets|=GADGETNAT2;
    }

  if (ecn) retval->gadgets|=GADGETECN;

  if (tstamp)
    {
    retval->uptime=tstamp/360000;
    retval->gadgets|=GADGETUPTIME;
    }

  return id;
  }
