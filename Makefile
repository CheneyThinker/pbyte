objects	= pebyte_base.o\
          pebyte_analyzer.o\
          pebyte_generator.o\
          pebyte.o

pebyte: $(objects)
	gcc -o $@ $(objects) -lm
	rm -rf *.o

%.o:	src/%.c
	gcc -c -o $@ $<

.PHONY:	clean

clean:
	rm -rf *.o pebyte
