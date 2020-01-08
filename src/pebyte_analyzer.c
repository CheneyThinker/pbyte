#include "../include/pebyte_analyzer.h"

int pebyte_analyzer(int argc, char** argv)
{
  FILE* pReadFile = fopen(argv[2], "r");
  if (pReadFile != NULL) {

    IMAGE_DOS_HEADER idh;
    fread(&idh, sizeof(IMAGE_DOS_HEADER), 1, pReadFile);
    image_dos_header(idh);

    #ifdef DOS_STUB
      dos_stub(pReadFile, idh.e_lfanew - sizeof(IMAGE_DOS_HEADER));
    #else
      fseek(pReadFile, idh.e_lfanew, SEEK_SET);
    #endif

    IMAGE_NT_HEADERS inh;
    fread(&inh, sizeof(IMAGE_NT_HEADERS), 1, pReadFile);
    printf("---IMAGE_NT_HEADERS---\n");
    printf("\t%08x\n", inh.signature);
    image_file_header(inh);
    image_optional_header(pReadFile, inh);
    printf("---IMAGE_NT_HEADERS---\n");

    image_section_header(pReadFile, inh.fileHeader.numberOfSections);

    //fseek(pReadFile, inh.optionalHeader.sizeOfHeaders, SEEK_SET);
  }
  fclose(pReadFile);
  return 0;
}

void image_dos_header(IMAGE_DOS_HEADER idh)
{
  printf("---IMAGE_DOS_HEADER---\n");
  printf("%04x\n", idh.e_magic);
  printf("%04x\n", idh.e_cblp);
  printf("%04x\n", idh.e_cp);
  printf("%04x\n", idh.e_crlc);
  printf("%04x\n", idh.e_cparhdr);
  printf("%04x\n", idh.e_minalloc);
  printf("%04x\n", idh.e_maxalloc);
  printf("%04x\n", idh.e_ss);
  printf("%04x\n", idh.e_sp);
  printf("%04x\n", idh.e_csum);
  printf("%04x\n", idh.e_ip);
  printf("%04x\n", idh.e_cs);
  printf("%04x\n", idh.e_lfarlc);
  printf("%04x\n", idh.e_ovno);
  for (byte index = 0; index < 4; index++)
  {
    printf("%04x\n", idh.e_res[index]);
  }
  printf("%04x\n", idh.e_oemid);
  printf("%04x\n", idh.e_oeminfo);
  for (byte index = 0; index < 10; index++)
  {
    printf("%04x\n", idh.e_res2[index]);
  }
  printf("%08x\n", idh.e_lfanew);
  printf("---IMAGE_DOS_HEADER---\n");
}

void dos_stub(FILE* pReadFile, dword pad)
{
  byte* pad_byte = (byte*) malloc(pad * sizeof(byte));
  for (dword pad_index = 0; pad_index < pad; pad_index++) {
    pad_byte[pad_index] = 0x00;
    fread(&pad_byte[pad_index], 1, 1, pReadFile);
  }
  printf("---dos_stub---\n");
  for (dword pad_index = 0; pad_index < pad; pad_index++) {
    if (pad_index) {
      printf(" ");
    }
    printf("%02x", pad_byte[pad_index]);
  }
  printf("\n---dos_stub---\n");
  free(pad_byte);
}

void image_file_header(IMAGE_NT_HEADERS inh)
{
  IMAGE_FILE_HEADER ifh = inh.fileHeader;
  printf("\t---IMAGE_FILE_HEADER---\n");
  printf("\t%04x\n", ifh.machine);
  printf("\t%04x\n", ifh.numberOfSections);
  printf("\t%08x\n", ifh.timeDateStamp);
  printf("\t%08x\n", ifh.pointerToSymbolTable);
  printf("\t%08x\n", ifh.numberOfSymbols);
  printf("\t%04x\n", ifh.sizeOfOptionalHeader);//if e0 32bit f0 64bit not change
  printf("\t%04x\n", ifh.characteristics);
  printf("\t---IMAGE_FILE_HEADER---\n");
}

void image_optional_header(FILE* pReadFile, IMAGE_NT_HEADERS inh) {
  IMAGE_OPTIONAL_HEADER ioh = inh.optionalHeader;
  printf("\t---IMAGE_OPTIONAL_HEADER---\n");
  printf("\t%04x\n", ioh.magic);//10b 32bit 20b 64bit
  printf("\t%02x\n", ioh.majorLinkerVersion);
  printf("\t%02x\n", ioh.minorLinkerVersion);
  printf("\t%08x\n", ioh.sizeOfCode);
  printf("\t%08x\n", ioh.sizeOfInitializedData);
  printf("\t%08x\n", ioh.sizeOfUninitializedData);
  printf("\t%08x\n", ioh.addressOfEntryPoint);
  printf("\t%08x\n", ioh.baseOfCode);
  printf("\t%08x\n", ioh.baseOfData);
#ifdef PLATFORM64
  printf("\t%08x%08x\n", (dword) ((ioh.imageBase >> 16) << 16), (dword) ((ioh.imageBase << 16) >> 16));
#else
  printf("\t%08x\n", ioh.imageBase);
#endif//addressOfEntryPoint + imageBase
  printf("\t%08x\n", ioh.sectionAlignment);
  printf("\t%08x\n", ioh.fileAlignment);
  printf("\t%04x\n", ioh.majorOperatingSystemVersion);
  printf("\t%04x\n", ioh.minorOperatingSystemVersion);
  printf("\t%04x\n", ioh.majorImageVersion);
  printf("\t%04x\n", ioh.minorImageVersion);
  printf("\t%04x\n", ioh.majorSubSystemVersion);
  printf("\t%04x\n", ioh.minorSubSystemVersion);
  printf("\t%08x\n", ioh.win32VersionValue);
  printf("\t%08x\n", ioh.sizeOfImage);
  printf("\t%08x\n", ioh.sizeOfHeaders);
  printf("\t%08x\n", ioh.checksum);
  printf("\t%04x\n", ioh.subSystem);
  printf("\t%04x\n", ioh.dllCharacteristics);
#ifdef PLATFORM64
  printf("\t%08x%08x\n", (dword) ((ioh.sizeOfStackReserve >> 16) << 16), (dword) ((ioh.sizeOfStackReserve << 16) >> 16));
  printf("\t%08x%08x\n", (dword) ((ioh.sizeOfStackCommit >> 16) << 16), (dword) ((ioh.sizeOfStackCommit << 16) >> 16));
  printf("\t%08x%08x\n", (dword) ((ioh.sizeOfHeapReserve >> 16) << 16), (dword) ((ioh.sizeOfHeapReserve << 16) >> 16));
  printf("\t%08x%08x\n", (dword) ((ioh.sizeOfHeapCommit >> 16) << 16), (dword) ((ioh.sizeOfHeapCommit << 16) >> 16));
#else
  printf("\t%08x\n", ioh.sizeOfStackReserve);
  printf("\t%08x\n", ioh.sizeOfStackCommit);
  printf("\t%08x\n", ioh.sizeOfHeapReserve);
  printf("\t%08x\n", ioh.sizeOfHeapCommit);
#endif
  printf("\t%08x\n", ioh.loaderFlags);
  printf("\t%08x\n", ioh.numberOfRvaAndSizes);
  image_data_directory(ioh.dataDirectory);
  printf("\t---IMAGE_OPTIONAL_HEADER---\n");
  fseek(pReadFile, inh.fileHeader.sizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER), SEEK_CUR);
}

void image_data_directory(PIMAGE_DATA_DIRECTORY pidd) {
  printf("\t\t---IMAGE_DATA_DIRECTORY---\n");
  for (byte index = 0; index < 0x10; index++) {
    printf("\t\t%08x %08x\n", pidd[index].virtualAddress, pidd[index].size);
  }
  printf("\t\t---IMAGE_DATA_DIRECTORY---\n");
}

void image_section_header(FILE* pReadFile, word numberOfSections) {
  printf("---IMAGE_SECTION_HEADER---\n");
  IMAGE_SECTION_HEADER ish[numberOfSections];
  for (word index = 0; index < numberOfSections; index++) {
    fread(&ish[index], sizeof(IMAGE_SECTION_HEADER), 1, pReadFile);
    printf("%s\n", ish[index].name);
    printf("%08x %08x\n", ish[index].misc.physicalAddress, ish[index].misc.virtualSize);
    printf("%08x\n", ish[index].virtualAddress);
    printf("%08x\n", ish[index].sizeOfRawData);
    printf("%08x\n", ish[index].pointerToRawData);
    printf("%08x\n", ish[index].pointerToRelocations);
    printf("%08x\n", ish[index].pointerToLinenumbers);
    printf("%04x\n", ish[index].numberOfRelocations);
    printf("%04x\n", ish[index].numberOfLinenumbers);
    printf("%08x\n", ish[index].characteristics);
  }
  printf("---IMAGE_SECTION_HEADER---\n");
}
