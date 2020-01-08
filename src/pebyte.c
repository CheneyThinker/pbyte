#include "../include/pebyte.h"

int main(int argc, char** argv)
{
  if (!strcasecmp(argv[1], "--analyzer")) {
    return pebyte_analyzer(argc, argv);
  } else if (!strcasecmp(argv[1], "--generator")) {
    return pebyte_generator(argc, argv);
  }
  return 0;
}
