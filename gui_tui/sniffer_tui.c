/* Interface semi-graphique ANSI — Windows (console VT) et Linux */

#include "../core/sniffer_core.h"
#include "../core/sniffer_console.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#endif

static volatile int g_quit;
static int g_alt_scr;

static void on_signal(int s) {
	(void)s;
	g_quit = 1;
}

#ifdef _WIN32
static int read_key_nonblock(void) {
	if (_kbhit())
		return _getch();
	return -1;
}
#else
static struct termios g_old;
static int g_tty_raw;

static void tty_restore(void) {
	if (g_tty_raw) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_old);
		g_tty_raw = 0;
	}
}

static void tty_raw_mode(void) {
	struct termios t;
	if (tcgetattr(STDIN_FILENO, &g_old) != 0)
		return;
	t = g_old;
	t.c_lflag &= ~(ICANON | ECHO);
	t.c_cc[VMIN] = 0;
	t.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
	g_tty_raw = 1;
	atexit(tty_restore);
}

static int read_key_nonblock(void) {
	fd_set fds;
	struct timeval tv = {0, 0};
	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds);
	if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) <= 0)
		return -1;
	char c;
	if (read(STDIN_FILENO, &c, 1) != 1)
		return -1;
	return (unsigned char)c;
}
#endif

static void scr_enter(void) {
	fputs("\033[?1049h\033[2J\033[H", stdout);
	fflush(stdout);
	g_alt_scr = 1;
}

static void scr_leave(void) {
	if (g_alt_scr) {
		fputs("\033[?1049l", stdout);
		fflush(stdout);
		g_alt_scr = 0;
	}
}

static void draw_header(int ndev, int sel, int capturing, const sniffer_stats_t *st) {
	sniffer_console_print(
	    "\033[1;36m Sniffer TUI \033[0m — interfaces:%d  capture:%s  pkts:%llu  drop:%llu\r\n",
	    ndev, capturing ? "\033[32mON\033[0m" : "\033[31mOFF\033[0m",
	    (unsigned long long)st->packets_captured, (unsigned long long)st->dropped);
	sniffer_console_print(
	    "\033[90m[S]tart [X] Stop [Up/Down] interface [Q]uit — root/admin requis\r\n\r\n\033[0m");
	for (int i = 0; i < ndev; i++) {
		char name[SNIFFER_DEV_NAME_LEN];
		char desc[SNIFFER_DEV_DESC_LEN];
		sniffer_device_get(i, name, sizeof(name), desc, sizeof(desc));
		if (i == sel)
			sniffer_console_print(" \033[48;5;236m\033[38;5;252m>[%d] %s\033[0m — %s\r\n", i,
			                      desc[0] ? desc : name, name);
		else
			sniffer_console_print("  [%d] %s — %s\r\n", i, desc[0] ? desc : name, name);
	}
	fputs("\r\n\033[1mFlux:\033[0m\r\n", stdout);
}

static void draw_screen(int ndev, int sel, int capturing, const sniffer_stats_t *st, int last_pkt_lines) {
	fputs("\033[H", stdout);
	draw_header(ndev, sel, capturing, st);
	for (int row = 0; row < last_pkt_lines; row++)
		fputs("\033[K\r\n", stdout);
	fflush(stdout);
}

int main(void) {
	signal(SIGINT, on_signal);
#ifndef _WIN32
	signal(SIGTERM, on_signal);
	tty_raw_mode();
#endif
	sniffer_console_init();
	scr_enter();

	if (sniffer_init() != 0) {
		sniffer_stats_t st;
		sniffer_stats(&st);
		fprintf(stderr, "Init: %s\n", st.last_error);
		scr_leave();
		return 1;
	}

	int sel = 0;
	int ndev = sniffer_device_count();
	if (ndev <= 0) {
		fputs("Aucune interface.\n", stderr);
		sniffer_shutdown();
		scr_leave();
		return 1;
	}

	char devname[SNIFFER_DEV_NAME_LEN];
	{
		char dummy[SNIFFER_DEV_DESC_LEN];
		sniffer_device_get(sel, devname, sizeof(devname), dummy, sizeof(dummy));
	}

	int last_sel = -1, last_cap = -1;
	uint64_t last_pkts = (uint64_t)-1;
	int pkt_lines = 0;
	int need_full = 1;

	while (!g_quit) {
		sniffer_stats_t st;
		sniffer_stats(&st);
		int k = read_key_nonblock();

		int capture_chg = (int)st.capturing != last_cap;
		int sel_chg = sel != last_sel;
		int pkt_chg = st.packets_captured != last_pkts;
		int key_evt = k >= 0;

		if (need_full || capture_chg || sel_chg || pkt_chg || key_evt) {
			draw_screen(ndev, sel, st.capturing, &st, pkt_lines);
			pkt_lines = 0;
			for (int n = 0; n < 12; n++) {
				sniffer_packet_t pkt;
				if (!sniffer_poll(&pkt))
					break;
				const char *p =
				    sniffer_proto_name(pkt.l4 != SNIFFER_PROTO_OTHER ? pkt.l4 : pkt.l3);
				sniffer_console_print(" \033[33m%llu\033[0m %-6s %-18s -> %-18s %s\r\n",
				                      (unsigned long long)pkt.timestamp_ms, p, pkt.src, pkt.dst,
				                      pkt.info);
				pkt_lines++;
			}
			last_sel = sel;
			last_cap = (int)st.capturing;
			last_pkts = st.packets_captured;
			need_full = 0;
			fflush(stdout);
		}

		if (k < 0) {
#ifdef _WIN32
			Sleep(120);
#else
			usleep(120000);
#endif
			continue;
		}
		if (k == 'q' || k == 'Q')
			break;
		if (k == 's' || k == 'S') {
			char dummy[SNIFFER_DEV_DESC_LEN];
			sniffer_device_get(sel, devname, sizeof(devname), dummy, sizeof(dummy));
			sniffer_stop();
			sniffer_start(devname, NULL);
			need_full = 1;
		}
		if (k == 'x' || k == 'X') {
			sniffer_stop();
			need_full = 1;
		}
#ifdef _WIN32
		if (k == 224 || k == 0) {
			int k2 = _getch();
			if (k2 == 72 && sel > 0)
				sel--;
			if (k2 == 80 && sel < ndev - 1)
				sel++;
			need_full = 1;
		}
#else
		if (k == 27) {
			int k2 = read_key_nonblock();
			if (k2 == '[') {
				int k3 = read_key_nonblock();
				if (k3 == 'A' && sel > 0)
					sel--;
				if (k3 == 'B' && sel < ndev - 1)
					sel++;
				need_full = 1;
			}
		}
#endif
	}

	sniffer_stop();
	sniffer_shutdown();
#ifndef _WIN32
	tty_restore();
#endif
	scr_leave();
	puts("Terminé.");
	return 0;
}
