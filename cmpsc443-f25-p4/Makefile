#
# File          : Makefile
# Description   : Build file for CMPSC443 project 1, applied cryptography
#                 


# Environment Setup
LIBDIRS=-L. -L/usr/lib64/
INCLUDES=-I. -I/usr/include/
CC=gcc 
CFLAGS=-c $(INCLUDES) -g -Wall
LINK=gcc -g
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cmpsc443-p4 \
	cmpsc443-p4-server
CMPSC443CRLIB=cmpsc443-crlib
CMPSC443CRLIBOBJS=cmpsc443-proto.o \
		 cmpsc443-network.o \
		 cmpsc443-ssl.o \
		 cmpsc443-util.o 
LIBS=-lcrypto -lm 

#
# Project Protections

p4 : $(TARGETS)

cmpsc443-p4 : cmpsc443-p4.o lib$(CMPSC443CRLIB).a
	$(LINK) $(LDFLAGS) cmpsc443-p4.o -l$(CMPSC443CRLIB) $(LIBS) -o $@

cmpsc443-p4-server : cmpsc443-p4.o lib$(CMPSC443CRLIB).a
	$(CC) $(CFLAGS) cmpsc443-p4.c -DCMPSC443_PROTOCOL_SERVER -o cmpsc443-p4-server.o 
	$(LINK) $(LDFLAGS) cmpsc443-p4-server.o -l$(CMPSC443CRLIB) $(LIBS) -o $@

lib$(CMPSC443CRLIB).a : $(CMPSC443CRLIBOBJS)
	$(AR) $@ $(CMPSC443CRLIBOBJS)
	$(RANLIB) $@

clean:
	rm -f *.o *~ $(TARGETS) lib$(CMPSC443CRLIB).a

BASENAME=p4
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cmpsc443-p4.c \
	    $(BASENAME)/cmpsc443-proto.c \
	    $(BASENAME)/cmpsc443-proto.h \
	    $(BASENAME)/cmpsc443-network.c \
	    $(BASENAME)/cmpsc443-network.h \
	    $(BASENAME)/cmpsc443-ssl.c \
	    $(BASENAME)/cmpsc443-ssl.h \
	    $(BASENAME)/cmpsc443-util.c \
	    $(BASENAME)/cmpsc443-util.h 
