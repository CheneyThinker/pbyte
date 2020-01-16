#include "../include/pebyte_base.h"

dword rva2foa(dword rva, word sectionAlignment, word numberOfSections, dword* virtualAddress, dword* sizeOfRawData, dword* pointerToRawData)
{
  dword foa = 0x00000000;
  if (rva < sectionAlignment)
  {
    foa = rva;
  }
  else
  {
    for (word index = 0x0000; index < numberOfSections; index = index + 0x0001)
    {
      if (rva >= virtualAddress[index] && rva <= (virtualAddress[index] + sizeOfRawData[index]))
      {
        foa = pointerToRawData[index] + rva - virtualAddress[index];
      }
    }
  }
  return foa;
}
