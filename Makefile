# Unix/Linux/macOS : make all
# Windows (MinGW/MSYS) : make all  OU  .\build.ps1 (recommandé)

CC      ?= gcc
AR      ?= ar
ROOT    := .
BUILD   := build
CORE    := $(ROOT)/core
ASM     := $(ROOT)/asm

CFLAGS  := -O2 -Wall -DSNIFFER_STATIC -I$(CORE)

UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
UNAME_M := $(shell uname -m 2>/dev/null || echo unknown)

# Détection Windows (MinGW, MSYS2, Git Bash, CYGWIN)
WIN :=
ifeq ($(OS),Windows_NT)
  WIN := 1
endif
ifneq (,$(findstring MINGW,$(UNAME_S)))
  WIN := 1
endif
ifneq (,$(findstring MSYS,$(UNAME_S)))
  WIN := 1
endif
ifneq (,$(findstring CYGWIN,$(UNAME_S)))
  WIN := 1
endif

ifeq ($(WIN),1)
  EXEEXT  := .exe
  LDFLAGS := -lws2_32
  ASM_SRC := $(ASM)/sniffer_x86.S
  ASM_OBJ := $(BUILD)/sniffer_x86_win.o
  GUI_BIN := $(BUILD)/sniffer_gui$(EXEEXT)
else
  EXEEXT  :=
  LDFLAGS := -pthread -ldl
  ifeq ($(UNAME_M),x86_64)
    ASM_SRC := $(ASM)/sniffer_x86_linux.S
    ASM_OBJ := $(BUILD)/sniffer_x86_linux.o
  else
    ASM_SRC :=
    ASM_OBJ :=
    CFLAGS  += -DSNIFFER_NO_ASM
  endif
  GUI_BIN :=
endif

CORE_SRC := $(CORE)/sniffer_core.c $(CORE)/sniffer_parse.c $(CORE)/sniffer_wpcap.c \
            $(CORE)/sniffer_util.c $(CORE)/sniffer_console.c $(CORE)/sniffer_insight.c \
            $(CORE)/sniffer_winproc.c

OBJS := $(addprefix $(BUILD)/,$(notdir $(CORE_SRC:.c=.o)))
ifneq ($(ASM_OBJ),)
  OBJS += $(ASM_OBJ)
else
  OBJS += $(BUILD)/sniffer_asm_port.o
endif

CLI_BIN := $(BUILD)/sniffer_cli$(EXEEXT)
TUI_BIN := $(BUILD)/sniffer_tui$(EXEEXT)

.PHONY: all clean cli tui gui help

all: cli tui
ifeq ($(WIN),1)
all: gui
endif

help:
	@echo "Sniffer — cibles: all, cli, tui, gui (Windows), clean"
ifeq ($(WIN),1)
	@echo "Plateforme: Windows (MinGW). Binaires: *$(EXEEXT)"
	@echo "Astuce: vous pouvez aussi lancer .\\build.ps1"
else
	@echo "Plateforme: $(UNAME_S) ($(UNAME_M))"
endif

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: $(CORE)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/sniffer_x86_win.o: $(ASM)/sniffer_x86.S | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/sniffer_x86_linux.o: $(ASM)/sniffer_x86_linux.S | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/sniffer_asm_port.o: $(CORE)/sniffer_asm_port.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/libsniffer_core.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

cli: $(CLI_BIN)

$(CLI_BIN): $(BUILD)/libsniffer_core.a cli/main.c
	$(CC) $(CFLAGS) -o $@ cli/main.c -L$(BUILD) -lsniffer_core $(LDFLAGS)

tui: $(TUI_BIN)

$(TUI_BIN): $(BUILD)/libsniffer_core.a gui_tui/sniffer_tui.c
	$(CC) $(CFLAGS) -o $@ gui_tui/sniffer_tui.c -L$(BUILD) -lsniffer_core $(LDFLAGS)

ifeq ($(WIN),1)
gui: $(GUI_BIN)

$(GUI_BIN): $(BUILD)/libsniffer_core.a gui_c/sniffer_gui.c
	$(CC) $(CFLAGS) -municode -mwindows -o $@ gui_c/sniffer_gui.c -L$(BUILD) -lsniffer_core \
		$(LDFLAGS) -lcomctl32 -lgdi32 -luxtheme -ldwmapi -liphlpapi -lpsapi -lgdiplus
endif

clean:
	rm -rf $(BUILD)
