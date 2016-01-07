ifdef CROSS
export CC = $(CROSS)-gcc
export CPP = $(CROSS)-gcc -E
export AR = $(CROSS)-ar
export RANLIB = $(CROSS)-ranlib
export LD = $(CROSS)-ld
else
export CC = gcc
export CPP = gcc -E
export AR = ar
export RANLIB = ranlib
export LD = ld
endif

#DEBUG=1

INCS = -I$(top_srcdir)/ -I$(top_srcdir)/config/ -I$(top_srcdir)/cmd_shell/lib/ -I$(top_srcdir)/cmd_shell
INCS += $(LIB_HEADER_INCS)
INCS += -I$(top_srcdir)/include/

#PROFILE = -pg
COMMON_CFLAGS += \
	$(PRIV_INCS) $(INCS) \
	-g -Wall -Wextra -std=gnu99 \
	-Wimplicit-function-declaration -fno-tree-pre -fno-strict-aliasing -Wno-unused-parameter \
	$(PROFILE)

ifdef DEBUG
COMMON_CFLAGS +=  -ggdb
else
COMMON_CFLAGS +=  -O2
endif

CFLAGS += $(COMMON_CFLAGS) $(PRIV_CFLAGS) $(PLATFORM_FLAGS)
#CFLAGS += $(PRIV_INCS) $(INCS) $(PRIV_CFLAGS)

LDFLAGS = -L$(top_srcdir)/.lib $(PRIV_LDFLAGS) $(LIB_LOAD_DIR)

#
# Common built targets:
#

ifdef SHARE_LIB
$(SHARE_LIB): $(SHARE_LIB_OBJS)
	$(CC) -shared -Wl,-soname -Wl,$(SHARE_LIB) -fPIC $(LDFLAGS) -o $@ $(SHARE_LIB_OBJS) $(PRIV_LIBS) -lc
	mkdir -p $(top_srcdir)/.lib
	cp -f $@ $(top_srcdir)/.lib
endif

ifdef STATIC_LIB
$(STATIC_LIB): $(STATIC_LIB_OBJS)
	$(AR) cru $@ $(STATIC_LIB_OBJS)
	$(RANLIB) $@
	mkdir -p $(top_srcdir)/.lib
	cp -f $@ $(top_srcdir)/.lib
endif

ifdef APPLICATION
$(APPLICATION): $(APPLICATION_OBJS) $(APPLICATION_LIBS)
	$(CC) -o $@ $(LDFLAGS) $(PRIV_LDFLAGS) $(APPLICATION_OBJS) $(APPLICATION_LIBS) $(PRIV_LIBS)
	mkdir -p $(top_srcdir)/.lib
	cp -f $@ $(top_srcdir)/.lib
endif

ifdef SUBDIRS
SUBDIRSTARGET=subdirs
.PHONY: $(SUBDIRSTARGET) $(SUBDIRS)

#ifeq ($(MAKECMDGOALS), x86)
#x86:$(SUBDIRSTARGET)
#endif

$(SUBDIRSTARGET): $(SUBDIRS)

$(SUBDIRS):
	@echo "===> $@"; \
	if [ -f "$@/Makefile" ]; then \
		$(MAKE)  -C $@ $(MAKECMDGOALS) || exit $$?; \
	fi; \
	echo "<=== $@";
endif

#
# Generating dependency files in .deps/ directory while compiling
#
DEPDIR = .deps
%.o:%.c 
	-@[ -d $(DEPDIR) ] || mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) -c $< -o $@ -MD -MF $(@:.o=.d)
	@OUTFILE=`echo $*.d | sed -e 's/\//_/g'` && \
	(cp $*.d $(DEPDIR)/$$OUTFILE; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
		    -e '/^$$/ d' -e 's/$$/ :/' < $*.d >> $(DEPDIR)/$$OUTFILE; \
		    rm -f $*.d)
		    
%.o:%.S
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPDIR)/*.d

DEPDIR = .deps
DEPFILE = $(DEPDIR)/$(subst /,_,$*.d)
%.o %.gcno: %.cpp
	-@[ -d $(DEPDIR) ] || mkdir -p $(DEPDIR)
	$(CC) $(CXXFLAGS) $(ARCHFLAGS) -c $< -o $(@:.gcno=.o) -MD -MP -MF $(DEPFILE)

#
# clean
#
.PHONY: clean
clean: $(SUBDIRSTARGET)
	-rm -rf *.o *.a *~ .deps
	-rm -rf ./.lib
ifdef SHARE_LIB
	-rm -rf $(SHARE_LIB) $(SHARE_LIB_OBJS)
endif
ifdef STATIC_LIB
	-rm -rf $(STATIC_LIB) $(STATIC_LIB_OBJS)
endif
ifdef APPLICATION
	-rm -rf $(APPLICATION) $(APPLICATION_OBJS)
endif
	-rm -f unit_test/data/actual*

realclean: clean
	@-rm -rf $(DEPDIR) *.d
