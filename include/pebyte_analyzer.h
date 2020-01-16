#pragma once

#ifndef PEBYTE_ANALYZER_H
#define PEBYTE_ANALYZER_H

#include "pebyte_base.h"

int pebyte_analyzer(int, char**);
void image_dos_header(FILE*, dword*);
void ms_dos_stub(FILE*, dword);
void coff_file_header(FILE*, word*, word*);
void image_optional_header(FILE*, dword*, dword*);
void image_data_directories(FILE*, dword, dword*, dword*);
void image_section_table(FILE*, word, dword*, dword*, dword*);
void image_section_item(FILE*, dword, dword*, dword*, dword, word, dword*, dword*, dword*);
void image_export_directory(FILE*);
void image_import_descriptor(FILE*, dword, word, dword*, dword*, dword*);
void image_resource_directory(FILE*);

#endif
