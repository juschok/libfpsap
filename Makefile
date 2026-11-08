##########################################################################
#
#  FairPlay SAP sender handshake — the dlopen'able crypto plugin (libfpsap).
#
#  Standalone, freestanding C plugin. Produces lib/$(OS)/$(ARCH)/libfpsap.$(LIB_SUFFIX),
#  which a host application loads at runtime (dlopen). The Apple-derived white-box
#  tables and the LGPL-licensed engine live here, not in the host binary.
#
#  Build:  make        (-> lib/<os>/<arch>/libfpsap.<suf>)
#          make check  (offline golden vectors)
#
##########################################################################

include Makefile.base

SRCDIR     = src
ENGINE_C   = $(SRCDIR)/fp_crypto.c $(SRCDIR)/fp_tables.c \
             $(SRCDIR)/fairplay_sapcore.c $(SRCDIR)/fairplay_bridge.c
PLUGIN_C   = $(SRCDIR)/fpsap_plugin.c
ENGINE_OBJ = $(ENGINE_C:$(SRCDIR)/%.c=$(OBJECT_DIR)/%.o)
PLUGIN_OBJ = $(PLUGIN_C:$(SRCDIR)/%.c=$(OBJECT_DIR)/%.o)

# -fvisibility=hidden so only the fpsap_* ABI is exported; engine stays internal.
FPSAP_CFLAGS = -std=c99 -Wall -Wextra -O3 -fPIC -fvisibility=hidden -I$(SRCDIR)

all: make_dirs $(LIB_DIR)/libfpsap.$(LIB_SUFFIX) strip

$(LIB_DIR)/libfpsap.$(LIB_SUFFIX): $(ENGINE_OBJ) $(PLUGIN_OBJ)
	$(CC) -shared -o $@ $(ENGINE_OBJ) $(PLUGIN_OBJ)

$(OBJECT_DIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(FPSAP_CFLAGS) -MD -MP -o $@ -c $<

make_dirs:
	$(MKDIR) $(OBJECT_DIR)
	$(MKDIR) $(LIB_DIR)

strip: $(LIB_DIR)/libfpsap.$(LIB_SUFFIX)
	@strip $(STRIP_FLAGS) $(LIB_DIR)/libfpsap.$(LIB_SUFFIX)

install: all
	$(MKDIR) $(PREFIX)/lib
	$(CP) $(LIB_DIR)/libfpsap.$(LIB_SUFFIX) $(PREFIX)/lib

# Offline conformance check: 142 golden vectors + message-body + session==frozen.
check: make_dirs
	$(CC) -std=c99 -Wall -Wextra -O2 -I$(SRCDIR) $(ENGINE_C) $(SRCDIR)/fp_test.c -o $(OBJECT_DIR)/fp_test
	$(OBJECT_DIR)/fp_test vectors

clean:
	$(RM) $(OBJECT_DIR)/*
	$(RM) $(LIB_DIR)/*

distclean:
	$(RM_RECURSIVE) .obj
	$(RM_RECURSIVE) lib

-include $(ENGINE_OBJ:.o=.d) $(PLUGIN_OBJ:.o=.d)
