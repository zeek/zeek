/* -*- mode: c++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 4 -*- */
/* vi: set expandtab shiftwidth=4 tabstop=4: */

/**
 * \file
 *
 * <pre>
 * Copyright &copy; 2007, Nick Galbreath -- nickg [at] modp [dot] com
 * All rights reserved.
 * http://code.google.com/p/stringencoders/
 * Released under the bsd license.
 * </pre>
 *
 * This defines signed/unsigned integer, and 'double' to char buffer
 * converters.  The standard way of doing this is with "sprintf", however
 * these functions are
 *   * guarenteed maximum size output
 *   * 5-20x faster!
 *   * core-dump safe
 *
 *
 */

#ifndef COM_MODP_STRINGENCODERS_NUMTOA_H
#define COM_MODP_STRINGENCODERS_NUMTOA_H

#ifdef __cplusplus
#define BEGIN_C extern "C" {
#define END_C }
#else
#define BEGIN_C
#define END_C
#endif

BEGIN_C

#include <stdint.h>

/** \brief convert an signed integer to char buffer
 *
 * \param[in] value
 * \param[out] buf the output buffer.  Should be 16 chars or more.
 */
void modp_itoa10(int32_t value, char* buf);

/** \brief convert an unsigned integer to char buffer
 *
 * \param[in] value
 * \param[out] buf The output buffer, should be 16 chars or more.
 */
void modp_uitoa10(uint32_t value, char* buf);

/** \brief convert an signed long integer to char buffer
 *
 * \param[in] value
 * \param[out] buf the output buffer.  Should be 24 chars or more.
 */
void modp_litoa10(int64_t value, char* buf);

/** \brief convert an unsigned long integer to char buffer
 *
 * \param[in] value
 * \param[out] buf The output buffer, should be 24 chars or more.
 */
void modp_ulitoa10(uint64_t value, char* buf);

/** \brief convert a floating point number to char buffer with
 *         fixed-precision format
 *
 * This is similar to "%.[0-9]f" in the printf style.  It will include
 * trailing zeros
 *
 * If the input value is greater than 1<<31, then the output format
 * will be switched exponential format.
 *
 * \param[in] value
 * \param[out] buf  The allocated output buffer.  Should be 32 chars or more.
 * \param[in] precision  Number of digits to the right of the decimal point.
 *    Can only be 0-9.
 */
void modp_dtoa(double value, char* buf, int precision);

/** \brief convert a floating point number to char buffer with a
 *         variable-precision format, and no trailing zeros
 *
 * This is similar to "%.[0-9]f" in the printf style, except it will
 * NOT include trailing zeros after the decimal point.  This type
 * of format oddly does not exists with printf.
 *
 * If the input value is greater than 1<<31, then the output format
 * will be switched exponential format.
 *
 * \param[in] value
 * \param[out] buf  The allocated output buffer.  Should be 32 chars or more.
 * \param[in] precision  Number of digits to the right of the decimal point.
 *    Can only be 0-9.
 */
void modp_dtoa2(double value, char* buf, int precision);

END_C

#endif
