#pragma once

#ifndef PEBYTE_ANALYZER_H
#define PEBYTE_ANALYZER_H

#include "pebyte_base.h"

int pebyte_analyzer(int, char**);
void dos_header(FILE*, dword*);
void ms_dos_stub(FILE*, dword);
void coff_file_header(FILE*, word*, word*);
void optional_header(FILE*, dword*, dword*);
void optional_header_data_directories(FILE*, dword, dword*, dword*);
void section_table(FILE*, word, dword*, dword*, dword*);
void optional_header_data_directories_item(FILE*, dword, dword*, dword*, dword, word, dword*, dword*, dword*);
void export_table(FILE*);
void import_table(FILE*, dword, word, dword*, dword*, dword*);
void resource_table(FILE*);
void exception_table(FILE*);
void certificate_table(FILE*);
void base_relocation_table(FILE*);
void debug(FILE*);
void architecture(FILE*);
void global_ptr(FILE*);
void tls_table(FILE*);
void load_config_table(FILE*);
void bound_import(FILE*);
void iat(FILE*);
void delay_import_descriptor(FILE*);
void clr_runtime_header(FILE*);
void reserved(FILE*);

#endif
