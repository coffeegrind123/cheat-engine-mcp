# Build the CE HTTP Bridge plugin DLL for Windows (x86_64) from Linux using MinGW.
#
# Requirements:
#   - mingw-w64 (apt: mingw-w64, dnf: mingw64-gcc-c++, brew: mingw-w64)
#   - Lua 5.3 headers (headers only — symbols come from CE's lua53-64.dll at runtime)
#
# The plugin MUST dynamically link against Cheat Engine's own lua53-64.dll — it
# shares CE's Lua state and a statically-linked Lua would have a different
# runtime, causing access violations. The import library plugin/lua53-64.a and
# its corresponding .def file are checked in.
#
# Usage:
#   make fetch-lua-headers    # first-time setup: download Lua 5.3.6 headers into vendor/
#   make                      # build build/ce_http_bridge.dll
#   make clean                # remove build artifacts

# MinGW cross-compiler. Override on the command line if your toolchain uses
# different names (e.g. `make MINGW_PREFIX=x86_64-w64-mingw32`).
MINGW_PREFIX ?= x86_64-w64-mingw32
CXX          := $(MINGW_PREFIX)-g++-posix
CC           := $(MINGW_PREFIX)-gcc-posix
AR           := $(MINGW_PREFIX)-ar
DLLTOOL      := $(MINGW_PREFIX)-dlltool

PLUGIN_DIR  = plugin
BUILD_DIR   = build
VENDOR_DIR  = vendor
LUA_VERSION ?= 5.3.6
LUA_SRC     ?= $(VENDOR_DIR)/lua-$(LUA_VERSION)/src

CXXFLAGS = -std=c++17 -O2 -DWIN32 -DNDEBUG -D_WINDOWS -D_USRDLL \
           -I$(PLUGIN_DIR) -I$(PLUGIN_DIR)/vendor -I$(LUA_SRC) \
           -Wall -Wno-write-strings -Wno-unused-variable

LDFLAGS = -shared -Wl,--out-implib,$(BUILD_DIR)/libce_http_bridge.a

# Static-link libstdc++ / libgcc / winpthread so the DLL depends only on
# standard Windows system libraries (KERNEL32, msvcrt, WS2_32) and CE's
# own lua53-64.dll (resolved at load time inside Cheat Engine).
LIBS = -static-libgcc -static-libstdc++ \
       -Wl,-Bstatic -lstdc++ -lpthread -Wl,-Bdynamic \
       -lws2_32 \
       $(PLUGIN_DIR)/lua53-64.a

SOURCES = $(PLUGIN_DIR)/main.cpp \
          $(PLUGIN_DIR)/ce_api.cpp \
          $(PLUGIN_DIR)/lua_bridge.cpp \
          $(PLUGIN_DIR)/http_server.cpp \
          $(PLUGIN_DIR)/handlers/process_handlers.cpp \
          $(PLUGIN_DIR)/handlers/memory_handlers.cpp \
          $(PLUGIN_DIR)/handlers/scan_handlers.cpp \
          $(PLUGIN_DIR)/handlers/analysis_handlers.cpp \
          $(PLUGIN_DIR)/handlers/debug_handlers.cpp \
          $(PLUGIN_DIR)/handlers/symbol_handlers.cpp \
          $(PLUGIN_DIR)/handlers/injection_handlers.cpp \
          $(PLUGIN_DIR)/handlers/table_handlers.cpp \
          $(PLUGIN_DIR)/handlers/structure_handlers.cpp \
          $(PLUGIN_DIR)/handlers/window_handlers.cpp \
          $(PLUGIN_DIR)/handlers/input_handlers.cpp \
          $(PLUGIN_DIR)/handlers/file_handlers.cpp \
          $(PLUGIN_DIR)/handlers/kernel_handlers.cpp \
          $(PLUGIN_DIR)/handlers/threading_handlers.cpp \
          $(PLUGIN_DIR)/handlers/misc_handlers.cpp

OBJECTS = $(patsubst $(PLUGIN_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SOURCES))

TARGET = $(BUILD_DIR)/ce_http_bridge.dll

.PHONY: all clean fetch-lua-headers check-lua-headers

all: check-lua-headers $(TARGET)

check-lua-headers:
	@if [ ! -f "$(LUA_SRC)/lua.h" ]; then \
		echo "ERROR: Lua headers not found at $(LUA_SRC)/lua.h"; \
		echo "Run 'make fetch-lua-headers' to download Lua $(LUA_VERSION) headers,"; \
		echo "or set LUA_SRC=/path/to/lua/src if you already have them."; \
		exit 1; \
	fi

fetch-lua-headers:
	@mkdir -p $(VENDOR_DIR)
	@if [ ! -d "$(VENDOR_DIR)/lua-$(LUA_VERSION)" ]; then \
		echo "Downloading Lua $(LUA_VERSION) (for headers only)..."; \
		curl -L https://www.lua.org/ftp/lua-$(LUA_VERSION).tar.gz | tar xz -C $(VENDOR_DIR); \
	fi
	@echo "Lua headers ready at $(VENDOR_DIR)/lua-$(LUA_VERSION)/src"

$(TARGET): $(OBJECTS) $(PLUGIN_DIR)/plugin.def
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(LDFLAGS) -o $@ $(OBJECTS) $(PLUGIN_DIR)/plugin.def $(LIBS)
	@echo "Built: $@"
	@ls -la $@

$(BUILD_DIR)/%.o: $(PLUGIN_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
