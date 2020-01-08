#pragma once

#ifndef PEBYTE_STRUCT_H
#define PEBYTE_STRUCT_H

#include "pebyte_def.h"

typedef struct _IMAGE_DOS_HEADER {
  word  e_magic;
  word  e_cblp;
  word  e_cp;
  word  e_crlc;
  word  e_cparhdr;
  word  e_minalloc;
  word  e_maxalloc;
  word  e_ss;
  word  e_sp;
  word  e_csum;
  word  e_ip;
  word  e_cs;
  word  e_lfarlc;
  word  e_ovno;
  word  e_res[4];
  word  e_oemid;
  word  e_oeminfo;
  word  e_res2[10];
  dword e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
  byte name[8];
  union {
    dword physicalAddress;
    dword virtualSize;
  } misc;
  dword virtualAddress;
  dword sizeOfRawData;
  dword pointerToRawData;
  dword pointerToRelocations;
  dword pointerToLinenumbers;
  word  numberOfRelocations;
  word  numberOfLinenumbers;
  dword characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  word  machine;
  word  numberOfSections;
  dword timeDateStamp;
  dword pointerToSymbolTable;
  dword numberOfSymbols;
  word  sizeOfOptionalHeader;
  word  characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
  word  magic;
  byte  majorLinkerVersion;
  byte  minorLinkerVersion;
  dword sizeOfCode;
  dword sizeOfInitializedData;
  dword sizeOfUninitializedData;
  dword addressOfEntryPoint;
  dword baseOfCode;
  dword baseOfData;
  dword imageBase;
  dword sectionAlignment;
  dword fileAlignment;
  word  majorOperatingSystemVersion;
  word  minorOperatingSystemVersion;
  word  majorImageVersion;
  word  minorImageVersion;
  word  majorSubSystemVersion;
  word  minorSubSystemVersion;
  dword win32VersionValue;
  dword sizeOfImage;
  dword sizeOfHeaders;
  dword checksum;
  word  subSystem;
  word  dllCharacteristics;
  dword sizeOfStackReserve;
  dword sizeOfStackCommit;
  dword sizeOfHeapReserve;
  dword sizeOfHeapCommit;
  dword loaderFlags;
  dword numberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY idds[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
  dword signature;
  IMAGE_FILE_HEADER ifh;
  IMAGE_OPTIONAL_HEADER ioh;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#endif
