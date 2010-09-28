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
#ifndef broccoli_config_h
#define broccoli_config_h

void          __bro_conf_init(void);
void          __bro_conf_set_domain(const char *domain);
void          __bro_conf_set_storage_domain(const char *domain);
const char   *__bro_conf_get_domain(void);

void          __bro_conf_add_int(const char *val_name, int val);
void          __bro_conf_add_dbl(const char *val_name, double val);
void          __bro_conf_add_str(const char *val_name, char *val);

int           __bro_conf_get_int(const char *val_name, int *val);
int           __bro_conf_get_dbl(const char *val_name, double *val);
const char *  __bro_conf_get_str(const char *val_name);

int           __bro_conf_forget_item(const char *val_name);

#endif
