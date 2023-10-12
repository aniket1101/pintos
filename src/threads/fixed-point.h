#ifndef FIXED_POINT_ARITHMETIC_H
#define FIXED_POINT_ARITHMETIC_H

#include <stdint.h>

#define FP_Q 14
#define FP_P 17

#define FP_F (1 << FP_Q)

#define INT_TO_FP(N) ((N) * FP_F)

#define FP_TO_INT_ROUND_ZERO(X) ((X) / FP_F)

#define FP_TO_NEAREST_INT(X) (((X) >= 0) ? (((X) + (FP_F / 2)) / FP_F) : \
                                   (((X) - (FP_F / 2)) / FP_F))

#define ADD_FPS(X, Y) ((X) + (Y))

#define SUB_FPS(X, Y) ((X) - (Y))

#define ADD_INT_AND_FP(X, N) ((X) + (INT_TO_FP(N)))

#define MULT_FPS(X, Y) (((int64_t) (X) * (Y)) / FP_F)

#define MULT_INT_TO_FP(X, N) ((X) * (N))

#define DIV_FPS(X, Y) (((int64_t) (X) * FP_F) / (Y))

#define DIV_FP_BY_INT(X, N) ((X) / (N))

#endif //FIXED_POINT_ARITHMETIC_H