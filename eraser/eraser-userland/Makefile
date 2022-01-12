EXEC=eraser
SRCDIR=src
DEPDIR=$(SRCDIR)/include
BUILDDIR=build
OBJDIR=$(BUILDDIR)/obj

_OBJ=main.o eraser.o utils.o crypto.o netlink.o tpm.o
OBJ=$(patsubst %,$(OBJDIR)/%,$(_OBJ))

_DEP=eraser.h utils.h crypto.h netlink.h tpm.h
DEP=$(patsubst %,$(DEPDIR)/%,$(_DEP))

CC=gcc
CFLAGS= -I$(DEPDIR) -Wall -Wno-pointer-sign -Wno-format -O2
LIBS=-lcrypto -ldevmapper -ltspi

all: dirs $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $^ -o $(BUILDDIR)/$@ $(LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(DEP)
	$(CC) $(CFLAGS) -c $< -o $@

dirs:
	mkdir -p $(BUILDDIR) $(OBJDIR)

debug: CFLAGS+=-DERASER_DEBUG
debug: all

notpm: CFLAGS+=-DERASER_NO_TPM -DERASER_DEBUG
notpm: all

install: all
	cp $(BUILDDIR)/$(EXEC) /usr/bin

.PHONY: clean
clean:
	rm -f $(OBJDIR)/*.o $(BUILDDIR)/$(EXEC)
	rm -df $(OBJDIR) $(BUILDDIR)
