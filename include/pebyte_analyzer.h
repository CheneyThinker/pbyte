#pragma once

#ifndef PEBYTE_ANALYZER_H
#define PEBYTE_ANALYZER_H

#include "pebyte_struct.h"

int pebyte_analyzer(int, char**);
void image_dos_header(IMAGE_DOS_HEADER);
void dos_stub(FILE*, dword);
void image_file_header(IMAGE_NT_HEADERS);
void image_optional_header(FILE*, IMAGE_NT_HEADERS);
void image_data_directory(PIMAGE_DATA_DIRECTORY);
void image_section_header(FILE*, word);

#endif
