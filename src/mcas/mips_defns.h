/*
Copyright (c) 2003, Keir Fraser All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
    * notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
    * copyright notice, this list of conditions and the following
    * disclaimer in the documentation and/or other materials provided
    * with the distribution.  Neither the name of the Keir Fraser
    * nor the names of its contributors may be used to endorse or
    * promote products derived from this software without specific
    * prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef __MIPS_DEFNS_H__
#define __MIPS_DEFNS_H__

#include <pthread.h>
#include <sched.h>

#ifndef MIPS
#define MIPS
#endif

#define _SC_NPROCESSORS_ONLN _SC_NPROC_ONLN

#define CACHE_LINE_SIZE 64


/*
 * I. Compare-and-swap.
 */

#define FAS32(_a, _n)                             \
({ __typeof__(_n) __r;                            \
   __asm__ __volatile__(                          \
       "1: ll   %0,%1     ;"                      \
       "   move $3,%2     ;"                      \
       "   sc   $3,%1     ;"                      \
       "   beqz $3,1b     ;"                      \
       : "=&r" (__r), "=m" (*(_a))                \
       :  "r" (_n) : "$3" );                      \
   __r;                                           \
})

#define FAS64(_a, _n)                             \
({ __typeof__(_n) __r;                            \
   __asm__ __volatile__(                          \
       "1: lld  %0,%1     ;"                      \
       "   move $3,%2     ;"                      \
       "   scd  $3,%1     ;"                      \
       "   beqz $3,1b     ;"                      \
       : "=&r" (__r), "=m" (*(_a))                \
       :  "r" (_n) : "$3" );                      \
   __r;                                           \
})

#define CAS32(_a, _o, _n)                         \
({ __typeof__(_o) __r;                            \
   __asm__ __volatile__(                          \
       "1: ll   %0,%1     ;"                      \
       "   bne  %0,%2,2f  ;"                      \
       "   move $3,%3     ;"                      \
       "   sc   $3,%1     ;"                      \
       "   beqz $3,1b     ;"                      \
       "2:                 "                      \
       : "=&r" (__r), "=m" (*(_a))                \
       :  "r" (_o), "r" (_n) : "$3" );            \
   __r;                                           \
})

#define CAS64(_a, _o, _n)                         \
({ __typeof__(_o) __r;                            \
   __asm__ __volatile__(                          \
       "1: lld  %0,%1     ;"                      \
       "   bne  %0,%2,2f  ;"                      \
       "   move $3,%3     ;"                      \
       "   scd  $3,%1     ;"                      \
       "   beqz $3,1b     ;"                      \
       "2:                 "                      \
       : "=&r" (__r), "=m" (*(_a))                \
       :  "r" (_o), "r" (_n) : "$3" );            \
   __r;                                           \
})

#define CAS(_x,_o,_n) ((sizeof (*_x) == 4)?CAS32(_x,_o,_n):CAS64(_x,_o,_n))
#define FAS(_x,_n)    ((sizeof (*_x) == 4)?FAS32(_x,_n)   :FAS64(_x,_n))
/* Update Integer location, return Old value. */
#define CASIO(_x,_o,_n) CAS(_x,_o,_n)
#define FASIO(_x,_n)    FAS(_x,_n)
/* Update Pointer location, return Old value. */
#define CASPO(_x,_o,_n) (void*)CAS((_x),(void*)(_o),(void*)(_n))
#define FASPO(_x,_n)    (void*)FAS((_x),(void*)(_n))
/* Update 32/64-bit location, return Old value. */
#define CAS32O CAS32
#define CAS64O CAS64

/*
 * II. Memory barriers.
 *  WMB(): All preceding write operations must commit before any later writes.
 *  RMB(): All preceding read operations must commit before any later reads.
 *  MB():  All preceding memory accesses must commit before any later accesses.
 *
 *  If the compiler does not observe these barriers (but any sane compiler
 *  will!), then VOLATILE should be defined as 'volatile'.
 */

#define MB()  __asm__ __volatile__ ("sync" : : : "memory")
#define WMB() MB()
#define RMB() MB()
#define VOLATILE /*volatile*/


/*
 * III. Cycle counter access.
 */

typedef unsigned long long tick_t;
#define RDTICK() \
    ({ tick_t __t; __asm__ __volatile__ ("dmfc0 %0,$9" : "=r" (__t)); __t; })


/*
 * IV. Types.
 */

typedef unsigned char      _u8;
typedef unsigned short     _u16;
typedef unsigned int       _u32;
typedef unsigned long long _u64;

#endif /* __INTEL_DEFNS_H__ */
