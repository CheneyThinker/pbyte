#pragma once

#ifndef PEBYTE_BASE_H
#define PEBYTE_BASE_H

#include "pebyte_def.h"

#define PRINTF_BYTE(declared)                          \
          byte declared;                               \
          fread(&declared, 1, sizeof(byte), pReadFile);\
          printf(#declared": %02x\n", declared);

#define PRINTF_WORD(declared)                          \
          word declared;                               \
          fread(&declared, 1, sizeof(word), pReadFile);\
          printf(#declared": %04x\n", declared);

#define PRINTF_DWORD(declared)                          \
          dword declared;                               \
          fread(&declared, 1, sizeof(dword), pReadFile);\
          printf(#declared": %08x\n", declared);

#define PRINTF_QWORD(declared)                          \
          qword declared;                               \
          fread(&declared, 1, sizeof(qword), pReadFile);\
          printf(#declared": %016lx\n", declared);

#define PRINTF_PWORD(declared)                        \
          fread(declared, 1, sizeof(word), pReadFile);\
          printf(#declared": %04x\n", *declared);

#define PRINTF_PDWORD(declared)                        \
          fread(declared, 1, sizeof(dword), pReadFile);\
          printf(#declared": %08x\n", *declared);

#define PRINTF_BYTE_ARR(declared, size)                  \
          byte declared;                                 \
          printf(#declared":");                          \
          for (byte index = 0; index < size; index++)    \
          {                                              \
            fread(&declared, 1, sizeof(byte), pReadFile);\
            printf(" %02x", declared);                   \
          }                                              \
          printf("\n");

#define PRINTF_WORD_ARR(declared, size)                  \
          word declared;                                 \
          printf(#declared":");                          \
          for (word index = 0; index < size; index++)    \
          {                                              \
            fread(&declared, 1, sizeof(word), pReadFile);\
            printf(" %04x", declared);                   \
          }                                              \
          printf("\n");

#define PRINTF_PDWORD_ARR(declared, index)                     \
          fread(&declared[index], 1, sizeof(dword), pReadFile);\
          printf(#declared": %08x\n", declared[index]);

#define PRINTF_STRING(declared)                                             \
          {                                                                 \
            byte declared;                                                  \
            printf(#declared": ");                                          \
            while (fread(&declared, 1, sizeof(byte), pReadFile) && declared)\
            {                                                               \
              printf("%c", declared);                                       \
            }                                                               \
            printf("\n");                                                   \
          }

dword rva2foa(dword, word, word, dword*, dword*, dword*);

#endif
