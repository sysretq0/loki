/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/include/types.h — Freestanding primitive types for Loki cave payload.
 */

#pragma once

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;

typedef signed char         s8;
typedef signed short        s16;
typedef signed int          s32;
typedef signed long long    s64;

typedef unsigned long       usize;
typedef signed long         ssize;
typedef unsigned long       uptr;

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)
typedef _Bool               bool;
#define true                1
#define false               0
#endif

#ifndef NULL
#define NULL                ((void *)0)
#endif
