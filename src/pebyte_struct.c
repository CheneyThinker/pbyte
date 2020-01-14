#include "../include/pebyte_struct.h"

dword rva2foa(dword rva, word numberOfSections, dword sectionAlignment, PIMAGE_SECTION_HEADER pish)
{
  for (word i = 0; i < numberOfSections; i++)
  {
    dword dwBlockCount = pish[i].sizeOfRawData / sectionAlignment + pish[i].sizeOfRawData % sectionAlignment ? 1 : 0;
    if (rva >= pish[i].virtualAddress && rva < (pish[i].virtualAddress + dwBlockCount * sectionAlignment))
    {
      return pish[i].pointerToRawData + rva - pish[i].virtualAddress;
    }
    else if (rva < pish[i].virtualAddress)
    {
      return rva;
    }
  }
  return 0x00000000;
}

dword foa2rva(dword foa, word numberOfSections, dword imageBase, PIMAGE_SECTION_HEADER pish)
{
  for (word i = 0; i < numberOfSections; i++)
  {
    if (foa >= pish[i].pointerToRawData && foa < (pish[i].pointerToRawData + pish[i].sizeOfRawData))
    {
      return imageBase + pish[i].virtualAddress + foa - pish[i].pointerToRawData;
    }
    else if (foa < pish[i].pointerToRawData)
    {
      return imageBase + foa;
    }
  }
  return 0x00000000;
}
