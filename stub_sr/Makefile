#------------------------------------------------------------------------------
# File: Makefile
#
# Note: This Makefile requires GNU make.
#
# (c) 2001,2000 Stanford University
#
#------------------------------------------------------------------------------

all : sr

CC = gcc

OSTYPE = $(shell uname)

ifeq ($(OSTYPE),CYGWIN_NT-5.1)
ARCH = -D_CYGWIN_
endif

ifeq ($(OSTYPE),Linux)
ARCH = -D_LINUX_
SOCK = -lnsl -lresolv
endif

ifeq ($(OSTYPE),SunOS)
ARCH =  -D_SOLARIS_
SOCK = -lnsl -lsocket -lresolv
endif

ifeq ($(OSTYPE),Darwin)
ARCH = -D_DARWIN_
SOCK = -lresolv
endif

CFLAGS = -g -Wall -std=c17 -D_DEBUG_ -DVNL $(ARCH)
CPPFLAGS = -g -Wall -std=c++17 -D_DEBUG_ -DVNL $(ARCH)

RELEASE_CFLAGS = -std=c17 -DVNL $(ARCH)
RELEASE_CPPFLAGS = -std=c++17 -DVNL $(ARCH)

LIBS= $(SOCK) -lm
PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER}
PURIFY= purify ${PFLAGS}

sr_SRCS = vnlconn.c  sr_main.c  \
          sr_if.c sr_rt.c sr_vns_comm.c   \
          sr_dumper.c sha1.c

sr_OBJS = $(patsubst %.c,%.o,$(sr_SRCS)) 
sr_DEPS = $(patsubst %.c,.%.d,$(sr_SRCS))

$(sr_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(sr_DEPS) : .%.d : %.c
	$(CC) -MM $(CFLAGS) $<  > $@

include $(sr_DEPS)	

sr_router:
	echo "REMEMBER: YOU'RE BUILDING WITH DEBUG ON" && \
	g++ -MM $(CPPFLAGS) sr_router.cc > .sr_router.d && \
	g++ -c $(CPPFLAGS) sr_router.cc -o sr_router.o


sr :  $(sr_OBJS) sr_router
	g++  -o sr sr_router.o $(sr_OBJS) $(LIBS)

sr.purify : $(sr_OBJS)
	$(PURIFY) $(CC) $(CPPFLAGS) -o sr.purify $(sr_OBJS) $(LIBS)


.PHONY : clean clean-deps dist

clean:
	rm -f *.o *~ core sr *.dump *.tar tags

clean-deps:
	rm -f .*.d

dist-clean: clean clean-deps
	rm -f .*.swp sr_stub.tar.gz

dist: dist-clean
	(cd ..; tar -X stub/exclude -cvf sr_stub.tar stub/; gzip sr_stub.tar); \
    mv ../sr_stub.tar.gz .

tags:
	ctags *.c

test:
	./sr -t 302 -r rtable -l logfile

sniff:
	tcpdump -r logfile -e -vvv -xx