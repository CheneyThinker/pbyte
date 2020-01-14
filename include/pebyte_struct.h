#pragma once

#ifndef PEBYTE_STRUCT_H
#define PEBYTE_STRUCT_H

#include "pebyte_def.h"

typedef struct _IMAGE_DOS_HEADER {// DOS .EXE header
  word  e_magic;                  // Magic number
  word  e_cblp;                   // Bytes on last page of file
  word  e_cp;                     // Pages in file
  word  e_crlc;                   // Relocations
  word  e_cparhdr;                // Size of header in paragraphs
  word  e_minalloc;               // Minimum extra paragraphs needed
  word  e_maxalloc;               // Maximum extra paragraphs needed
  word  e_ss;                     // Initial (relative) SS value
  word  e_sp;                     // Initial SP value
  word  e_csum;                   // Checksum
  word  e_ip;                     // Initial IP value
  word  e_cs;                     // Initial (relative) CS value
  word  e_lfarlc;                 // File address of relocation table
  word  e_ovno;                   // Overlay number
  word  e_res[4];                 // Reserved words
  word  e_oemid;                  // OEM identifier (for e_oeminfo)
  word  e_oeminfo;                // OEM information; e_oemid specific
  word  e_res2[10];               // Reserved words
  dword e_lfanew;                 // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

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
  dword virtualAddress;
  dword size;
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
  IMAGE_DATA_DIRECTORY dataDirectory[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
  dword signature;
  IMAGE_FILE_HEADER fileHeader;
  IMAGE_OPTIONAL_HEADER optionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY {
  dword characteristics;
  dword timeDateStamp;
  word  majorVersion;
  word  minorVersion;
  dword name;
  dword base;
  dword numberOfFunctions;
  dword numberOfNames;
  dword addressOfFunctions;
  dword addressOfNames;
  dword addressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
    dword characteristics;
    dword originalFirstThunk;//INT
  } dummyunionname;
  dword timeDateStamp;
  dword forwarderChain;
  dword name;
  dword firstThunk;//IAT
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA {
  union {
    dword forwarderString;
    dword function;
    dword ordinal;
    dword addressOfData;
  } u1;
} IMAGE_THUNK_DATA, *PIMAGE_THUNK_DATA;

typedef struct _IMAGE_IMPORT_BY_NAME {
  word hint;
  byte name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
  dword characteristics;
  dword timeDateStamp;
  word  majorVersion;
  word  minorVersion;
  word  numberOfNamedEntries;
  word  numberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
  dword beginAddress;
  dword endAddress;
  dword unwindInfoAddress;
} _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

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

dword rva2foa(dword, word, dword, PIMAGE_SECTION_HEADER);
dword foa2rva(dword, word, dword, PIMAGE_SECTION_HEADER);

#endif
