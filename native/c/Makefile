CC ?= clang
CFLAGS ?= -std=c11 -O3 -Wall -Wextra -Werror -pedantic -fPIC -I.
LDFLAGS ?=

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	SHARED_LIB = libruntime_fastpath.dylib
	SHARED_FLAG = -dynamiclib
else
	SHARED_LIB = libruntime_fastpath.so
	SHARED_FLAG = -shared
endif

OBJS = cantilever_der_fastpath.o cantilever_gf256.o
TEST_BIN = bin/test_fastpath

.PHONY: all test clean

all: $(SHARED_LIB) $(TEST_BIN)

$(SHARED_LIB): $(OBJS)
	$(CC) $(SHARED_FLAG) -o $@ $(OBJS) $(LDFLAGS)

cantilever_der_fastpath.o: cantilever_der_fastpath.c cantilever_native.h
	$(CC) $(CFLAGS) -c $< -o $@

cantilever_gf256.o: cantilever_gf256.c cantilever_native.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): test_fastpath.c $(OBJS)
	@mkdir -p bin
	$(CC) $(CFLAGS) test_fastpath.c $(OBJS) -o $@ $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf *.o *.so *.dylib bin/
