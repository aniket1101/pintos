#include <stdio.h>
#include <stdint.h>

#define FP_Q 14
#define FP_P 17

#define FP_F (1 << FP_Q)

#define TO_FP (n) (n * FP_F)

#define TO_INT_ZERO (x) (x / FP_F)

#define TO_INT_NEAREST (x) x > 0 ? (x + (FP_F / 2)) / FP_F : \
                                   (x - (FP_F / 2)) / FP_F

#define ADD (x, y) (x + y)

#define SUB (x, y) (x - y)

#define ADD_FP (x, n) (x + (n * FP_F))

#define MULT_FP (x, y) ((((int64_t) x) * y) / FP_F)

#define MULT (x, n) (x * n)

#define DIV_FP (x, y) ((((int64_t) x) * FP_F) / y)

#define DIV (x, n) (x / n)