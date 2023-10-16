#ifndef FIXED_POINT_ARITHMETIC_H
#define FIXED_POINT_ARITHMETIC_H

#include <stdint.h>

typedef int64_t fp_t;

#define FP_Q 14
#define FP_P 17

#define FP_F (1 << FP_Q)

// REMEMBER: FP IS A BIG INTEGER, NOT A C FLOAT

// Takes in int and returns FP
#define INT_TO_FP(N) ((N) * FP_F) 

// Takes in FP and returns int
#define FP_TO_INT_ROUND_ZERO(X) (X / FP_F) 

// Takes in FP and returns int
#define FP_TO_NEAREST_INT(X) (((X) >= 0) ? ((X + (FP_F / 2)) / FP_F) : \
                                   (((INT_TO_FP(X)) - (FP_F / 2)) / FP_F)) 

// Takes in 2 FP and returns FP
#define ADD_FPS(X, Y) ((X) + (Y)) 

// Takes in 2 FP and returns FP
#define SUB_FPS(X, Y) ((X) - (Y)) 

// Takes in an FP and one int and returns FP
#define ADD_FP_AND_INT(X, N) ((X) + (INT_TO_FP(N))) 

// Takes in an FP and one int and returns FP
#define SUB_FP_AND_INT(X, N) ((X) - (INT_TO_FP(N)))

// Takes in 2 FP and returns FP
#define MULT_FPS(X, Y) (((int64_t) (X) * (Y)) / FP_F) 

// Takes in 1 FP and one int and returns FP
#define MULT_FP_BY_INT(X, N) ((X) * (N)) 

// Takes in 2 FP and returns FP
#define DIV_FPS(X, Y) (((int64_t) (X) * FP_F) / (Y))

// Takes in FP and int and returns FP
#define DIV_FP_BY_INT(X, N) ((X) / (N))

#endif //FIXED_POINT_ARITHMETIC_H