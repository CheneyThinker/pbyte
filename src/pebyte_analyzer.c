#include "../include/pebyte_analyzer.h"

int pebyte_analyzer(int argc, char** argv)
{
  FILE* pReadFile = fopen(argv[2], "r");
  if (pReadFile != NULL)
  {
    dword e_lfanew;
    image_dos_header(pReadFile, &e_lfanew);

    ms_dos_stub(pReadFile, e_lfanew);

    PRINTF_DWORD(signature)

    word numberOfSections;
    word sizeOfOptionalHeader;
    coff_file_header(pReadFile, &numberOfSections, &sizeOfOptionalHeader);

    dword sectionAlignment;
    dword numberOfRvaAndSizes;
    image_optional_header(pReadFile, &sectionAlignment, &numberOfRvaAndSizes);

    dword virtualAddress[numberOfRvaAndSizes];
    dword size[numberOfRvaAndSizes];
    image_data_directories(pReadFile, numberOfRvaAndSizes, virtualAddress, size);

    dword sectionVirtualAddress[numberOfSections];
    dword sizeOfRawData[numberOfSections];
    dword pointerToRawData[numberOfSections];
    image_section_table(pReadFile, numberOfSections, sectionVirtualAddress, sizeOfRawData, pointerToRawData);

    image_section_item(pReadFile, numberOfRvaAndSizes, virtualAddress, size, sectionAlignment, numberOfSections, sectionVirtualAddress, sizeOfRawData, pointerToRawData);

  }
  fclose(pReadFile);
  return 0;
}

void image_dos_header(FILE* pReadFile, dword* e_lfanew)
{
  printf("***IMAGE_DOS_HEADER***\n");
  PRINTF_WORD(e_magic)
  PRINTF_WORD(e_cblp)
  PRINTF_WORD(e_cp)
  PRINTF_WORD(e_crlc)
  PRINTF_WORD(e_cparhdr)
  PRINTF_WORD(e_minalloc)
  PRINTF_WORD(e_maxalloc)
  PRINTF_WORD(e_ss)
  PRINTF_WORD(e_sp)
  PRINTF_WORD(e_csum)
  PRINTF_WORD(e_ip)
  PRINTF_WORD(e_cs)
  PRINTF_WORD(e_lfarlc)
  PRINTF_WORD(e_ovno)
  PRINTF_WORD_ARR(e_res, E_RES_SIZE)
  PRINTF_WORD(e_oemid)
  PRINTF_WORD(e_oeminfo)
  PRINTF_WORD_ARR(e_res2, E_RES2_SIZE)
  PRINTF_PDWORD(e_lfanew)
  printf("***IMAGE_DOS_HEADER***\n");
}

void ms_dos_stub(FILE* pReadFile, dword e_lfanew)
{
  printf("***MS_DOS_STUB***\n");
  #ifdef SKIP_DOS_STUB
    fseek(pReadFile, e_lfanew - IMAGE_DOS_HEADER_SIZE, SEEK_CUR);
  #else
    dword address = 0x00000040;
    dword size = e_lfanew - IMAGE_DOS_HEADER_SIZE;
    byte dos_stub[size];
    fread(dos_stub, 1, size * sizeof(byte), pReadFile);
    for (dword index = 0; index < size; index++)
    {
      if (!(index % 0x00000010))
      {
        if (index)
        {
          printf("\n");
        }
        printf("%08x:", address);
        address = address + 0x00000010;
      }
      printf(" %02x", dos_stub[index]);
    }
    if (size % 0x00000010)
    {
      printf("\n");
    }
  #endif
  printf("***MS_DOS_STUB***\n");
}

void coff_file_header(FILE* pReadFile, word* numberOfSections, word* sizeOfOptionalHeader)
{
  printf("***COFF_FILE_HEADER***\n");
  PRINTF_WORD(machine)
  PRINTF_PWORD(numberOfSections)
  PRINTF_DWORD(timeDateStamp)
  PRINTF_DWORD(pointerToSymbolTable)
  PRINTF_DWORD(numberOfSymbols)
  PRINTF_PWORD(sizeOfOptionalHeader)
  PRINTF_WORD(characteristics)
  printf("***COFF_FILE_HEADER***\n");
}

void image_optional_header(FILE* pReadFile, dword* sectionAlignment, dword* numberOfRvaAndSizes)
{
  printf("***IMAGE_OPTIONAL_HEADER***\n");
  PRINTF_WORD(magic)
  PRINTF_BYTE(majorLinkerVersion)
  PRINTF_BYTE(minorLinkerVersion)
  PRINTF_DWORD(sizeOfCode)
  PRINTF_DWORD(sizeOfInitializedData)
  PRINTF_DWORD(sizeOfUninitializedData)
  PRINTF_DWORD(addressOfEntryPoint)
  PRINTF_DWORD(baseOfCode)
  if (magic == 0x010b)
  {
    PRINTF_DWORD(baseOfData)
    PRINTF_DWORD(imageBase)
  }
  else if (magic == 0x020b)
  {
    PRINTF_QWORD(imageBase)
  }
  PRINTF_PDWORD(sectionAlignment)
  PRINTF_DWORD(fileAlignment)
  PRINTF_WORD(majorOperatingSystemVersion)
  PRINTF_WORD(minorOperatingSystemVersion)
  PRINTF_WORD(majorImageVersion)
  PRINTF_WORD(minorImageVersion)
  PRINTF_WORD(majorSubsystemVersion)
  PRINTF_WORD(minorSubsystemVersion)
  PRINTF_DWORD(win32VersionValue)
  PRINTF_DWORD(sizeOfImage)
  PRINTF_DWORD(sizeOfHeaders)
  PRINTF_DWORD(checkSum)
  PRINTF_WORD(subsystem)
  PRINTF_WORD(dllCharacteristics)
  if (magic == 0x010b)
  {
    PRINTF_DWORD(sizeOfStackReserve)
    PRINTF_DWORD(sizeOfStackCommit)
    PRINTF_DWORD(sizeOfHeapReserve)
    PRINTF_DWORD(sizeOfHeapCommit)
  }
  else if (magic == 0x020b)
  {
    PRINTF_QWORD(sizeOfStackReserve)
    PRINTF_QWORD(sizeOfStackCommit)
    PRINTF_QWORD(sizeOfHeapReserve)
    PRINTF_QWORD(sizeOfHeapCommit)
  }
  PRINTF_DWORD(loaderFlags)
  PRINTF_PDWORD(numberOfRvaAndSizes)
  printf("***IMAGE_OPTIONAL_HEADER***\n");
}

void image_data_directories(FILE* pReadFile, dword numberOfRvaAndSizes, dword* virtualAddress, dword* size)
{
  printf("***IMAGE_DATA_DIRECTORIES***\n");
  for (dword index = 0x00000000; index < numberOfRvaAndSizes; index = index + 0x00000001)
  {
    PRINTF_PDWORD_ARR(virtualAddress, index)
    PRINTF_PDWORD_ARR(size, index)
  }
  printf("***IMAGE_DATA_DIRECTORIES***\n");
}

void image_section_table(FILE* pReadFile, word numberOfSections, dword* virtualAddress, dword* sizeOfRawData, dword* pointerToRawData)
{
  printf("***IMAGE_SECTION_TABLE***\n");
  for (word index = 0x0000; index < numberOfSections; index = index + 0x0001)
  {
    byte name[8];
    fread(name, 1, sizeof(byte) * 8, pReadFile);
    printf("name: %s\n", name);
    /*for (byte count = 0x00; count < 0x08; count = count + 0x01)
      {
        printf(" %02x", name[count]);
      }
      printf("\n");*/
    PRINTF_DWORD(virtualSize)
    PRINTF_PDWORD_ARR(virtualAddress, index)
    PRINTF_PDWORD_ARR(sizeOfRawData, index)
    PRINTF_PDWORD_ARR(pointerToRawData, index)
    PRINTF_DWORD(pointerToRelocations)
    PRINTF_DWORD(pointerToLinenumbers)
    PRINTF_WORD(numberOfRelocations)
    PRINTF_WORD(numberOfLinenumbers)
    PRINTF_DWORD(characteristics)
  }
  printf("***IMAGE_SECTION_TABLE***\n");
}

void image_section_item(FILE* pReadFile, dword numberOfRvaAndSizes, dword* virtualAddress, dword* size, dword sectionAlignment, word numberOfSections, dword* sectionVirtualAddress, dword* sizeOfRawData, dword* pointerToRawData)
{
  printf("***IMAGE_SECTION_TABLE_ITEM***\n");
  for (dword index = 0x00000000; index < numberOfRvaAndSizes; index = index + 0x00000001)
  {
    if (size[index])
    {
      fpos_t pos;
      fgetpos(pReadFile, &pos);
      dword foa = rva2foa(virtualAddress[index], sectionAlignment, numberOfSections, sectionVirtualAddress, sizeOfRawData, pointerToRawData);
      fseek(pReadFile, foa, SEEK_SET);
      switch (index)
      {
        case 0x00000000:
          image_export_directory(pReadFile);
          break;
        case 0x00000001:
          image_import_descriptor(pReadFile, sectionAlignment, numberOfSections, sectionVirtualAddress, sizeOfRawData, pointerToRawData);
          break;
        case 0x00000002:
          image_resource_directory(pReadFile);
          break;
        case 0x00000003:
          break;
      }
      fsetpos(pReadFile, &pos);
    }
  }
  printf("***IMAGE_SECTION_TABLE_ITEM***\n");
}

void image_export_directory(FILE* pReadFile)
{
  printf("***IMAGE_SECTION_TABLE_ITEM EXPORT***\n");
  PRINTF_DWORD(characteristics)
  PRINTF_DWORD(timeDateStamp)
  PRINTF_WORD(majorVersion)
  PRINTF_WORD(minorVersion)
  PRINTF_DWORD(name)
  PRINTF_DWORD(base)
  PRINTF_DWORD(numberOfFunctions)
  PRINTF_DWORD(numberOfNames)
  PRINTF_DWORD(addressOfFunctions)
  PRINTF_DWORD(addressOfNames)
  PRINTF_DWORD(addressOfNameOrdinals)

  fseek(pReadFile, name, SEEK_SET);
  byte name_str;
  while (fread(&name_str, 1, 1, pReadFile) && name_str)
  {
    printf("%c", name_str);
  }
  printf("\n");

  fseek(pReadFile, addressOfFunctions, SEEK_SET);
  dword addressOfFunctions_[numberOfFunctions];
  fread(addressOfFunctions_, 1, sizeof(dword) * numberOfFunctions, pReadFile);
  for (dword index = 0; index < numberOfFunctions; index++)
  {
    if (!(index % 0x00000010))
    {
      if (index)
      {
        printf("\n");
      }
      printf("%08x", addressOfFunctions_[index]);
    }
    else
    {
      printf(" %08x", addressOfFunctions_[index]);
    }
  }
  printf("\n");

  fseek(pReadFile, addressOfNames, SEEK_SET);
  dword addressOfNames_[numberOfNames];
  fread(addressOfNames_, 1, sizeof(dword) * numberOfNames, pReadFile);
  for (dword index = 0; index < numberOfNames; index++)
  {
    printf("%08x ", addressOfNames_[index]);
    fseek(pReadFile, addressOfNames_[index], SEEK_SET);
    while (fread(&name_str, 1, 1, pReadFile) && name_str)
    {
      printf("%c", name_str);
    }
    printf("\n");
  }

  fseek(pReadFile, addressOfNameOrdinals, SEEK_SET);
  word addressOfNameOrdinals_[numberOfNames];
  fread(addressOfNameOrdinals_, 1, sizeof(word) * numberOfNames, pReadFile);
  for (dword index = 0; index < numberOfNames; index++)
  {
    if (!(index % 0x0000001e))
    {
      if (index)
      {
        printf("\n");
      }
      printf("%04x", addressOfNameOrdinals_[index]);
    } else {
      printf(" %04x", addressOfNameOrdinals_[index]);
    }
  }
  printf("\n");
  printf("***IMAGE_SECTION_TABLE_ITEM EXPORT***\n");
}

void image_import_descriptor(FILE* pReadFile, dword sectionAlignment, word numberOfSections, dword* sectionVirtualAddress, dword* sizeOfRawData, dword* pointerToRawData)
{
  printf("***IMAGE_SECTION_TABLE_ITEM IMPORT***\n");
  while (1)
  {
    PRINTF_DWORD(characteristics)
    PRINTF_DWORD(timeDateStamp)
    PRINTF_DWORD(forwarderChain)
    PRINTF_DWORD(name)
    PRINTF_DWORD(firstThunk)
    if (characteristics || timeDateStamp || forwarderChain || name || firstThunk)
    {
      fpos_t pos;
      fgetpos(pReadFile, &pos);
      dword name_foa = rva2foa(name, sectionAlignment, numberOfSections, sectionVirtualAddress, sizeOfRawData, pointerToRawData);
      fseek(pReadFile, name_foa, SEEK_SET);
      byte name_str;
      while (fread(&name_str, 1, 1, pReadFile) && name_str)
      {
        printf("%c", name_str);
      }
      printf("\n");
      //image_thunk_data(pReadFile, characteristics);//originalFirstThunk = characteristics
      fsetpos(pReadFile, &pos);
    }
    else
    {
      break;
    }
  }
  printf("***IMAGE_SECTION_TABLE_ITEM IMPORT***\n");
}

void image_resource_directory(FILE* pReadFile)
{
  printf("***IMAGE_SECTION_TABLE_ITEM RESOURCE***\n");
  while (1)
  {
    PRINTF_DWORD(characteristics)
    PRINTF_DWORD(timeDateStamp)
    PRINTF_WORD(majorVersion)
    PRINTF_WORD(minorVersion)
    PRINTF_WORD(numberOfNamedEntries)
    PRINTF_WORD(numberOfIdEntries)
    if (characteristics || timeDateStamp || majorVersion || minorVersion || numberOfNamedEntries || numberOfIdEntries)
    {
    }
    else
    {
      break;
    }
  }
  printf("***IMAGE_SECTION_TABLE_ITEM RESOURCE***\n");
}

/*
void image_thunk_data(FILE* pReadFile, dword originalFirstThunk)
{
  printf("\t\t\t\t---IMAGE_THUNK_DATA---\n");
  fseek(pReadFile, originalFirstThunk, SEEK_SET);
  IMAGE_THUNK_DATA itd;
  byte counter = 0x00;
  fpos_t position;
  while (fread(&itd, 1, sizeof(IMAGE_THUNK_DATA), pReadFile) && itd.u1.forwarderString)
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
    fgetpos(pReadFile, &position);
    fseek(pReadFile, itd.u1.forwarderString, SEEK_SET);
    IMAGE_IMPORT_BY_NAME iibn;
    fread(&iibn, 1, sizeof(IMAGE_IMPORT_BY_NAME), pReadFile);
    printf("%04x\n", iibn.hint);
    fsetpos(pReadFile, &position);
  }
  if (counter)
  {
    printf("\n");
  }
  printf("\t\t\t\t---IMAGE_THUNK_DATA---\n");
}
*/
