#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

// #define __DEBUG__
// #define __HEX_DUMP__

#ifdef __DEBUG__ 
  #define PUTBUF_FORMAT(format, ...) ({\
      char out[100];\
      putbuf(out, snprintf(out, 100, format "\n", __VA_ARGS__));\
    })
  #define PUTBUF(str) (PUTBUF_FORMAT(str "%s", ""))
#else
  #define PUTBUF_FORMAT(format, ...)
  #define PUTBUF(str) 
#endif

#ifdef __HEX_DUMP__ 
  #define HEX_DUMP_ESP(esp) (hex_dump((uint32_t) esp, esp, PHYS_BASE - esp, 1))
#else 
  #define HEX_DUMP_ESP(esp)
#endif

#endif