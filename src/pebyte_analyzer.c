#include "../include/pebyte_analyzer.h"

int pebyte_analyzer(int argc, char** argv)
{
  FILE* pReadFile = fopen(argv[2], "r");
  if (pReadFile != NULL) {
    IMAGE_DOS_HEADER idh;
    fread(&idh, sizeof(IMAGE_DOS_HEADER), 1, pReadFile);
    printf("%04x\n", swap_word(idh.e_magic));
    printf("%04x\n", swap_word(idh.e_cblp));
    printf("%04x\n", swap_word(idh.e_cp));
    printf("%04x\n", swap_word(idh.e_crlc));
    printf("%04x\n", swap_word(idh.e_cparhdr));
    printf("%04x\n", swap_word(idh.e_minalloc));
    printf("%04x\n", swap_word(idh.e_maxalloc));
    printf("%04x\n", swap_word(idh.e_ss));
    printf("%04x\n", swap_word(idh.e_sp));
    printf("%04x\n", swap_word(idh.e_csum));
    printf("%04x\n", swap_word(idh.e_ip));
    printf("%04x\n", swap_word(idh.e_cs));
    printf("%04x\n", swap_word(idh.e_lfarlc));
    printf("%04x\n", swap_word(idh.e_ovno));
    for (byte index = 0; index < 4; index++) {
      printf("%04x\n", swap_word(idh.e_res[index]));
    }
    printf("%04x\n", swap_word(idh.e_oemid));
    printf("%04x\n", swap_word(idh.e_oeminfo));
    for (byte index = 0; index < 10; index++) {
      printf("%04x\n", swap_word(idh.e_res2[index]));
    }
    #ifdef LITTLE_ENDIAN
      printf("%08x\n", idh.e_lfanew);
      fseek(pReadFile, idh.e_lfanew, SEEK_SET);
    #else
      printf("%08x\n", swap_dword(idh.e_lfanew));
      fseek(pReadFile, swap_dword(idh.e_lfanew), SEEK_SET);
    #endif
    IMAGE_NT_HEADERS inh;
    fread(&inh, sizeof(IMAGE_NT_HEADERS), 1, pReadFile);
    printf("%08x\n", swap_dword(inh.signature));
    printf("%04x\n", swap_word(inh.ifh.machine));
    printf("%04x\n", swap_word(inh.ifh.numberOfSections));
    printf("%08x\n", swap_dword(inh.ifh.timeDateStamp));
    printf("%08x\n", swap_dword(inh.ifh.pointerToSymbolTable));
    printf("%08x\n", swap_dword(inh.ifh.numberOfSymbols));
    printf("%04x\n", swap_word(inh.ifh.sizeOfOptionalHeader));
    printf("%04x\n", swap_word(inh.ifh.characteristics));
  }
  fclose(pReadFile);
  return 0;
}
