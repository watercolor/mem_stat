top_srcdir=.
SHARE_LIB = libmmstat.so
SRCEXTS = .c

SHARE_LIB_OBJS=mmstat.o
PRIV_CFLAGS+="-std=c99"
PRIV_CFLAGS+=-I. -Wall -g -fPIC
PRIV_LIBS += -ldl -lpthread

include $(top_srcdir)/common.make
