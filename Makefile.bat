@echo off
gcc -c src/*.c
gcc -o pebyte *.o
del *.o
cmd /k