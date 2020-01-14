#include "../include/pebyte_analyzer.h"

int pebyte_analyzer(int argc, char** argv)
{
  FILE* pReadFile = fopen(argv[2], "r");
  if (pReadFile != NULL)
  {
    image_dos_header(pReadFile);
    image_nt_headers(pReadFile);
    //fseek(pReadFile, inh.optionalHeader.sizeOfHeaders, SEEK_SET);
  }
  fclose(pReadFile);
  return 0;
}

void image_dos_header(FILE* pReadFile)
{
  printf("---IMAGE_DOS_HEADER---\n");
  IMAGE_DOS_HEADER idh;
  fread(&idh, sizeof(IMAGE_DOS_HEADER), 1, pReadFile);
  printf("e_magic:    %04x\n", idh.e_magic);
  printf("e_cblp:     %04x\n", idh.e_cblp);
  printf("e_cp:       %04x\n", idh.e_cp);
  printf("e_crlc:     %04x\n", idh.e_crlc);
  printf("e_cparhdr:  %04x\n", idh.e_cparhdr);
  printf("e_minalloc: %04x\n", idh.e_minalloc);
  printf("e_maxalloc: %04x\n", idh.e_maxalloc);
  printf("e_ss:       %04x\n", idh.e_ss);
  printf("e_sp:       %04x\n", idh.e_sp);
  printf("e_csum:     %04x\n", idh.e_csum);
  printf("e_ip:       %04x\n", idh.e_ip);
  printf("e_cs:       %04x\n", idh.e_cs);
  printf("e_lfarlc:   %04x\n", idh.e_lfarlc);
  printf("e_ovno:     %04x\n", idh.e_ovno);
  printf("e_res:     ");
  for (byte index = 0; index < 4; index++)
  {
    printf(" %04x", idh.e_res[index]);
  }
  printf("\n");
  printf("e_oemid:    %04x\n", idh.e_oemid);
  printf("e_oeminfo:  %04x\n", idh.e_oeminfo);
  printf("e_res2:    ");
  for (byte index = 0; index < 10; index++)
  {
    printf(" %04x", idh.e_res2[index]);
  }
  printf("\n");
  printf("e_lfanew:   %08x\n", idh.e_lfanew);
  printf("---IMAGE_DOS_HEADER---\n");
  #ifdef DOS_STUB
    dos_stub(pReadFile, idh.e_lfanew - sizeof(IMAGE_DOS_HEADER));
  #else
    fseek(pReadFile, idh.e_lfanew, SEEK_SET);
  #endif
}

void dos_stub(FILE* pReadFile, dword pad)
{
  printf("---DOS_STUB---\n");
  byte pad_byte[pad];
  for (dword pad_index = 0; pad_index < pad; pad_index++)
  {
    pad_byte[pad_index] = 0x00;
    fread(&pad_byte[pad_index], 1, 1, pReadFile);
    if (pad_index)
    {
      printf(" ");
    }
    printf("%02x", pad_byte[pad_index]);
  }
  printf("\n---DOS_STUB---\n");
}

void image_nt_headers(FILE* pReadFile)
{
  printf("---IMAGE_NT_HEADERS---\n");
  IMAGE_NT_HEADERS inh;
  fread(&inh, sizeof(IMAGE_NT_HEADERS), 1, pReadFile);
  printf("signature: %08x\n", inh.signature);
  image_file_header(inh.fileHeader);
  image_optional_header(pReadFile, inh.optionalHeader, inh.fileHeader.sizeOfOptionalHeader, inh.fileHeader.numberOfSections);
  printf("---IMAGE_NT_HEADERS---\n");
}

void image_file_header(IMAGE_FILE_HEADER ifh)
{
  printf("\t---IMAGE_FILE_HEADER---\n");
  printf("\tmachine:              %04x\n", ifh.machine);
  printf("\tnumberOfSections:     %04x\n", ifh.numberOfSections);
  printf("\ttimeDateStamp:        %08x\n", ifh.timeDateStamp);
  printf("\tpointerToSymbolTable: %08x\n", ifh.pointerToSymbolTable);
  printf("\tnumberOfSymbols:      %08x\n", ifh.numberOfSymbols);
  printf("\tsizeOfOptionalHeader: %04x\n", ifh.sizeOfOptionalHeader);//if e0 32bit f0 64bit not change
  printf("\tcharacteristics:      %04x\n", ifh.characteristics);
  printf("\t---IMAGE_FILE_HEADER---\n");
}

void image_optional_header(FILE* pReadFile, IMAGE_OPTIONAL_HEADER ioh, word sizeOfOptionalHeader, word numberOfSections)
{
  printf("\t---IMAGE_OPTIONAL_HEADER---\n");
  printf("\tmagic:                       %04x\n", ioh.magic);//10b 32bit 20b 64bit
  printf("\tmajorLinkerVersion:          %02x\n", ioh.majorLinkerVersion);
  printf("\tminorLinkerVersion:          %02x\n", ioh.minorLinkerVersion);
  printf("\tsizeOfCode:                  %08x\n", ioh.sizeOfCode);
  printf("\tsizeOfInitializedData:       %08x\n", ioh.sizeOfInitializedData);
  printf("\tsizeOfUninitializedData:     %08x\n", ioh.sizeOfUninitializedData);
  printf("\taddressOfEntryPoint:         %08x\n", ioh.addressOfEntryPoint);
  printf("\tbaseOfCode:                  %08x\n", ioh.baseOfCode);
  printf("\tbaseOfData:                  %08x\n", ioh.baseOfData);
  printf("\timageBase:                   %08x\n", ioh.imageBase);//addressOfEntryPoint + imageBase
  printf("\tsectionAlignment:            %08x\n", ioh.sectionAlignment);
  printf("\tfileAlignment:               %08x\n", ioh.fileAlignment);
  printf("\tmajorOperatingSystemVersion: %04x\n", ioh.majorOperatingSystemVersion);
  printf("\tminorOperatingSystemVersion: %04x\n", ioh.minorOperatingSystemVersion);
  printf("\tmajorImageVersion:           %04x\n", ioh.majorImageVersion);
  printf("\tminorImageVersion:           %04x\n", ioh.minorImageVersion);
  printf("\tmajorSubSystemVersion:       %04x\n", ioh.majorSubSystemVersion);
  printf("\tminorSubSystemVersion:       %04x\n", ioh.minorSubSystemVersion);
  printf("\twin32VersionValue:           %08x\n", ioh.win32VersionValue);
  printf("\tsizeOfImage:                 %08x\n", ioh.sizeOfImage);
  printf("\tsizeOfHeaders:               %08x\n", ioh.sizeOfHeaders);
  printf("\tchecksum:                    %08x\n", ioh.checksum);
  printf("\tsubSystem:                   %04x\n", ioh.subSystem);
  printf("\tdllCharacteristics:          %04x\n", ioh.dllCharacteristics);
  printf("\tsizeOfStackReserve:          %08x\n", ioh.sizeOfStackReserve);
  printf("\tsizeOfStackCommit:           %08x\n", ioh.sizeOfStackCommit);
  printf("\tsizeOfHeapReserve:           %08x\n", ioh.sizeOfHeapReserve);
  printf("\tsizeOfHeapCommit:            %08x\n", ioh.sizeOfHeapCommit);
  printf("\tloaderFlags:                 %08x\n", ioh.loaderFlags);
  printf("\tnumberOfRvaAndSizes:         %08x\n", ioh.numberOfRvaAndSizes);
  //image_data_directory(pReadFile, ioh.dataDirectory);
  printf("\t---IMAGE_OPTIONAL_HEADER---\n");
  fseek(pReadFile, sizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER), SEEK_CUR);
  image_section_header(pReadFile, numberOfSections);
}

void image_data_directory(FILE* pReadFile, PIMAGE_DATA_DIRECTORY pidd)
{
  printf("\t\t---IMAGE_DATA_DIRECTORY---\n");
  for (byte index = 0; index < 0x10; index++)
  {
    printf("\t\tvirtualAddress: %08x size: %08x\n", pidd[index].virtualAddress, pidd[index].size);
    fseek(pReadFile, pidd[index].virtualAddress, SEEK_SET);
    switch (index)
    {
      case 0x00:
        image_export_directory(pReadFile);
        break;
      case 0x01:
        image_import_descriptor(pReadFile);
        break;
      case 0x02:
        image_resource_directory(pReadFile);
        break;
    }
  }
  printf("\t\t---IMAGE_DATA_DIRECTORY---\n");
}

void image_export_directory(FILE* pReadFile) {
  IMAGE_EXPORT_DIRECTORY ied;
  fread(&ied, sizeof(IMAGE_EXPORT_DIRECTORY), 1, pReadFile);
  printf("\t\t\t---IMAGE_EXPORT_DIRECTORY---\n");
  printf("\t\t\tcharacteristics:       %08x\n", ied.characteristics);
  printf("\t\t\ttimeDateStamp:         %08x\n", ied.timeDateStamp);
  printf("\t\t\tmajorVersion:          %04x\n", ied.majorVersion);
  printf("\t\t\tminorVersion:          %04x\n", ied.minorVersion);
  printf("\t\t\tname:                  %08x ", ied.name);
  fseek(pReadFile, ied.name, SEEK_SET);
  byte name = 0x00;
  while (fread(&name, 1, 1, pReadFile) && name)
  {
    printf("%c", name);
    name = 0x00;
  }
  printf("\n");
  printf("\t\t\tbase:                  %08x\n", ied.base);
  printf("\t\t\tnumberOfFunctions:     %08x\n", ied.numberOfFunctions);
  printf("\t\t\tnumberOfNames:         %08x\n", ied.numberOfNames);
  printf("\t\t\taddressOfFunctions:    %08x\n", ied.addressOfFunctions);
  fseek(pReadFile, ied.addressOfFunctions, SEEK_SET);
  dword addressOfFunctions[ied.numberOfFunctions];
  fread(addressOfFunctions, sizeof(dword) * ied.numberOfFunctions, 1, pReadFile);
  for (dword index = 0; index < ied.numberOfFunctions; index++) {
    if (!(index % 0x0000000c)) {
      if (index) {
        printf("\n");
      }
      printf("\t\t\t\t%08x", addressOfFunctions[index]);
    } else {
      printf(" %08x", addressOfFunctions[index]);
    }
  }
  printf("\n");
  printf("\t\t\taddressOfNames:        %08x\n", ied.addressOfNames);
  fseek(pReadFile, ied.addressOfNames, SEEK_SET);
  dword addressOfNames[ied.numberOfNames];
  fread(addressOfNames, sizeof(dword) * ied.numberOfNames, 1, pReadFile);
  for (dword index = 0; index < ied.numberOfNames; index++) {
    printf("\t\t\t\t%08x ", addressOfNames[index]);
    fseek(pReadFile, addressOfNames[index], SEEK_SET);
    byte name = 0x00;
    while (fread(&name, 1, 1, pReadFile) && name) {
      printf("%c", name);
    }
    printf("\n");
  }
  printf("\t\t\taddressOfNameOrdinals: %08x\n", ied.addressOfNameOrdinals);
  fseek(pReadFile, ied.addressOfNameOrdinals, SEEK_SET);
  word addressOfNameOrdinals[ied.numberOfNames];
  fread(addressOfNameOrdinals, sizeof(word) * ied.numberOfNames, 1, pReadFile);
  for (dword index = 0; index < ied.numberOfNames; index++) {
    if (!(index % 0x00000014)) {
      if (index) {
        printf("\n");
      }
      printf("\t\t\t\t%04x", addressOfNameOrdinals[index]);
    } else {
      printf(" %04x", addressOfNameOrdinals[index]);
    }
  }
  printf("\n");
  printf("\t\t\t---IMAGE_EXPORT_DIRECTORY---\n");
}

void image_import_descriptor(FILE* pReadFile) {
  printf("\t\t\t---IMAGE_IMPORT_DESCRIPTOR---\n");
  IMAGE_IMPORT_DESCRIPTOR iid;
  fpos_t position;
  while (fread(&iid, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pReadFile) && (iid.dummyunionname.characteristics || iid.timeDateStamp || iid.forwarderChain || iid.name || iid.firstThunk)) {
    printf("\t\t\tcharacteristics: %08x originalFirstThunk: %08x\n", iid.dummyunionname.characteristics, iid.dummyunionname.originalFirstThunk);
    printf("\t\t\ttimeDateStamp:   %08x\n", iid.timeDateStamp);
    printf("\t\t\tforwarderChain:  %08x\n", iid.forwarderChain);
    printf("\t\t\tname:            %08x\n", iid.name);
    printf("\t\t\tfirstThunk:      %08x\n", iid.firstThunk);
    fgetpos(pReadFile, &position);
    image_thunk_data(pReadFile, iid.dummyunionname.originalFirstThunk);
    fsetpos(pReadFile, &position);
  }
  printf("\t\t\t---IMAGE_IMPORT_DESCRIPTOR---\n");
}

void image_thunk_data(FILE* pReadFile, dword originalFirstThunk)
{
  printf("\t\t\t\t---IMAGE_THUNK_DATA---\n");
  fseek(pReadFile, originalFirstThunk, SEEK_SET);
  IMAGE_THUNK_DATA itd;
  byte counter = 0x00;
  while (fread(&itd, sizeof(IMAGE_THUNK_DATA), 1, pReadFile) && itd.u1.forwarderString)
  {
    if (counter == 0x00)
    {
      counter = counter + 0x01;
      printf("\t\t\t\t%08x", itd.u1.forwarderString);//itd.u1.function, itd.u1.ordinal, itd.u1.addressOfData
    }
    else if (counter == 0x09)
    {
      counter = 0x00;
      printf(" %08x\n", itd.u1.forwarderString);
    }
    else
    {
      counter = counter + 0x01;
      printf(" %08x", itd.u1.forwarderString);
    }
  }
  if (counter)
  {
    printf("\n");
  }
  printf("\t\t\t\t---IMAGE_THUNK_DATA---\n");
  /*fseek(pReadFile, forwarderString, SEEK_SET);
  IMAGE_IMPORT_BY_NAME iibn;
  fread(&iibn, sizeof(IMAGE_IMPORT_BY_NAME), 1, pReadFile);
  printf("%04x %ld\n", iibn.hint, sizeof(iibn.name) / sizeof(byte));
  word index = 0x0000;
  while (iibn.name[index]) {
    printf("%02x", iibn.name[index++]);
  }
  printf("\n");*/
}

void image_resource_directory(FILE* pReadFile) {
  printf("\t\t\t---IMAGE_RESOURCE_DIRECTORY---\n");
  IMAGE_RESOURCE_DIRECTORY ird;
  while (fread(&ird, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pReadFile) && (ird.characteristics || ird.timeDateStamp || ird.majorVersion || ird.minorVersion || ird.numberOfNamedEntries || ird.numberOfIdEntries)) {
    printf("\t\t\tcharacteristics:      %08x\n", ird.characteristics);
    printf("\t\t\ttimeDateStamp:        %08x\n", ird.timeDateStamp);
    printf("\t\t\tmajorVersion:         %04x\n", ird.majorVersion);
    printf("\t\t\tminorVersion:         %04x\n", ird.minorVersion);
    printf("\t\t\tnumberOfNamedEntries: %04x\n", ird.numberOfNamedEntries);
    printf("\t\t\tnumberOfIdEntries:    %04x\n", ird.numberOfIdEntries);
  }
  printf("\t\t\t---IMAGE_RESOURCE_DIRECTORY---\n");
}

void image_section_header(FILE* pReadFile, word numberOfSections) {
  printf("\t---IMAGE_SECTION_HEADER---\n");
  IMAGE_SECTION_HEADER ish[numberOfSections];
  for (word index = 0; index < numberOfSections; index++) {
    fread(&ish[index], sizeof(IMAGE_SECTION_HEADER), 1, pReadFile);
    printf("\tname:                 %s\n", ish[index].name);
    printf("\tphysicalAddress:      %08x virtualSize: %08x\n", ish[index].misc.physicalAddress, ish[index].misc.virtualSize);
    printf("\tvirtualAddress:       %08x\n", ish[index].virtualAddress);
    printf("\tsizeOfRawData:        %08x\n", ish[index].sizeOfRawData);
    printf("\tpointerToRawData:     %08x\n", ish[index].pointerToRawData);
    printf("\tpointerToRelocations: %08x\n", ish[index].pointerToRelocations);
    printf("\tpointerToLinenumbers: %08x\n", ish[index].pointerToLinenumbers);
    printf("\tnumberOfRelocations:  %04x\n", ish[index].numberOfRelocations);
    printf("\tnumberOfLinenumbers:  %04x\n", ish[index].numberOfLinenumbers);
    printf("\tcharacteristics:      %08x\n", ish[index].characteristics);
  }
  printf("\t---IMAGE_SECTION_HEADER---\n");
}
