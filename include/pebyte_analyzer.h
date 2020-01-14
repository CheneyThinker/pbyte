#pragma once

#ifndef PEBYTE_ANALYZER_H
#define PEBYTE_ANALYZER_H

#include "pebyte_struct.h"

int pebyte_analyzer(int, char**);
void image_dos_header(FILE*);
void dos_stub(FILE*, dword);
void image_nt_headers(FILE*);
void image_file_header(IMAGE_FILE_HEADER);
void image_optional_header(FILE*, IMAGE_OPTIONAL_HEADER, word, word);
void image_data_directory(FILE*, PIMAGE_DATA_DIRECTORY);
void image_export_directory(FILE*);
void image_import_descriptor(FILE*);
void image_thunk_data(FILE*, dword);
void image_resource_directory(FILE*);

void image_section_header(FILE*, word);

#endif
