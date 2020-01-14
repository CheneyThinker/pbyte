#!/bin/bash
gcc -c src/*.c
gcc -o pebyte *.o
rm *.o
