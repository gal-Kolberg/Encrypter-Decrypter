CC = gcc
CC_MTA = -lmta_crypt -lmta_rand -pthread -L`pwd`

SRCS := $(subst ./,,$(shell find . -maxdepth 1 -name "*.c"))
OBJECTS := $(patsubst %.c, %.out, $(SRCS))

all: $(SRCS) $(OBJECTS)

%.out: %.c
	$(CC) $< $(CC_MTA) -o $@

clean:
	rm *.out