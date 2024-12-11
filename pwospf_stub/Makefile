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
SOCK = -lnsl
endif

ifeq ($(OSTYPE),SunOS)
ARCH =  -D_SOLARIS_
SOCK = -lnsl -lsocket
endif

ifeq ($(OSTYPE),Darwin)
ARCH = -D_DARWIN_
SOCK =
endif

CFLAGS = -g -Wall -std=c17 -D_DEBUG_ -DVNL $(ARCH)
CPPFLAGS = -g -Wall -std=c++17 -D_DEBUG_ -DVNL $(ARCH)

RELEASE_CFLAGS = -std=c17 -O3 -DVNL $(ARCH)
RELEASE_CPPFLAGS = -std=c++17 -O3 -DVNL $(ARCH)

LIBS= $(SOCK) -lm -lresolv -lpthread
PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER}
PURIFY= purify ${PFLAGS}

sr_SRCS = vnlconn.c sr_main.c  \
          sr_if.c sr_rt.c sr_vns_comm.c   \
          sr_dumper.c sha1.c 

sr_OBJS = $(patsubst %.c,%.o,$(sr_SRCS))
sr_DEPS = $(patsubst %.c,.%.d,$(sr_SRCS))

$(sr_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(sr_DEPS) : .%.d : %.c
	$(CC) -MM $(CFLAGS) $<  > $@

include $(sr_DEPS)	

sr_pwospf:
	g++ -MM $(CPPFLAGS) sr_pwospf.cc > .sr_pwospf.d && \
	g++ -c $(CPPFLAGS) sr_pwospf.cc -o sr_pwospf.o

sr_router:
	g++ -MM $(CPPFLAGS) sr_router.cc > .sr_router.d && \
	g++ -c $(CPPFLAGS) sr_router.cc -o sr_router.o 


sr :   $(sr_OBJS)  sr_router sr_pwospf
	g++ $(CPPFLAGS) -o sr sr_router.o  sr_pwospf.o $(sr_OBJS) $(LIBS)

sr.purify : $(sr_OBJS)
	$(PURIFY) $(CC) $(CPPFLAGS) -o sr.purify $(sr_OBJS) $(LIBS)


.PHONY : clean clean-deps dist

clean:
	rm -f *.o *~ core sr *.dump *.tar tags

clean-deps:
	rm -f .*.d

dist-clean: clean clean-deps
	rm -f .*.swp pwospf_stub.tar.gz

dist: dist-clean
	(cd ..; tar -X pwospf_stub/exclude -cvf pwospf_stub.tar pwospf_stub/; gzip pwospf_stub.tar); \
    mv ../pwospf_stub.tar.gz .

tags:
	ctags *.c

test-static: sr
	./sr -t 103 -v vhost1 -r rtable.vhost1 -l logfile.vhost1
	./sr -t 103 -v vhost2 -r rtable.vhost2 -l logfile.vhost2 > /dev/null 
	./sr -t 103 -v vhost3 -r rtable.vhost3 -l logfile.vhost3 > /dev/null 

test: stop sr 
	./sr -t 103 -v vhost1 -r rtable.net -l logfile.vhost1  > /dev/null & \
	./sr -t 103 -v vhost2 -r rtable.empty -l logfile.vhost2 > /dev/null  & \
	./sr -t 103 -v vhost3 -r rtable.empty -l logfile.vhost3 > /dev/null
	
stop:
	pkill -f sr

sniff:
	tcpdump -r logfile.vhost1 -e -vvv -xx