/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_BENCH_H
#define SECP256K1_BENCH_H

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "sys/time.h"


# if defined(__GNUC__)
#   define ALWAYS_INLINE SECP256K1_INLINE __attribute__((__always_inline__))
# elif defined(_MSC_VER) && !defined(__clang__)
#   define ALWAYS_INLINE SECP256K1_INLINE __forceinline
# elif defined(__CLANG__) && __has_attribute(__always_inline__)
#   define ALWAYS_INLINE SECP256K1_INLINE __attribute__((__always_inline__))
# else
#   define ALWAYS_INLINE SECP256K1_INLINE
# endif

/* A memory fence to prevent compiler optimizations
   It tells the optimizer that it can do whatever it wants with *p so the optimizer can't optimize *p out.
   The nice thing is that because the assembly is actually empty it doesn't add any instrcutions
   *Notice: This is a best effort, nothing promise us it will always work.* */
ALWAYS_INLINE static void memory_fence(void *p) {
    __asm__ __volatile__("": : "g"(p) : "memory");
}

static double gettimedouble(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_usec * 0.000001 + tv.tv_sec;
}

void print_number(double x) {
    double y = x;
    int c = 0;
    if (y < 0.0) {
        y = -y;
    }
    while (y > 0 && y < 100.0) {
        y *= 10.0;
        c++;
    }
    printf("%.*f", c, x);
}

void run_benchmark(char *name, void (*benchmark)(void*), void (*setup)(void*), void (*teardown)(void*), void* data, int count, int iter) {
    int i;
    double min = HUGE_VAL;
    double sum = 0.0;
    double max = 0.0;
    for (i = 0; i < count; i++) {
        double begin, total;
        if (setup != NULL) {
            setup(data);
        }
        begin = gettimedouble();
        benchmark(data);
        total = gettimedouble() - begin;
        if (teardown != NULL) {
            teardown(data);
        }
        if (total < min) {
            min = total;
        }
        if (total > max) {
            max = total;
        }
        sum += total;
    }
    printf("%s: min ", name);
    print_number(min * 1000000.0 / iter);
    printf("us / avg ");
    print_number((sum / count) * 1000000.0 / iter);
    printf("us / max ");
    print_number(max * 1000000.0 / iter);
    printf("us\n");
}

int have_flag(int argc, char** argv, char *flag) {
    char** argm = argv + argc;
    argv++;
    if (argv == argm) {
        return 1;
    }
    while (argv != NULL && argv != argm) {
        if (strcmp(*argv, flag) == 0) {
            return 1;
        }
        argv++;
    }
    return 0;
}

#endif /* SECP256K1_BENCH_H */
