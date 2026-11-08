#include "sniffer_console.h"

#include <stdarg.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

void sniffer_console_init(void) {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	if (h != INVALID_HANDLE_VALUE) {
		DWORD mode = 0;
		if (GetConsoleMode(h, &mode))
			SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}
#endif
}

void sniffer_console_print(const char *fmt, ...) {
	char buf[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

#ifdef _WIN32
	HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD cmode = 0;
	if (hout != INVALID_HANDLE_VALUE && GetConsoleMode(hout, &cmode)) {
		wchar_t wbuf[4096];
		int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buf, -1, wbuf, 4096);
		if (n <= 0)
			n = MultiByteToWideChar(CP_ACP, 0, buf, -1, wbuf, 4096);
		if (n > 0) {
			DWORD written = 0;
			WriteConsoleW(hout, wbuf, (DWORD)(n - 1), &written, NULL);
			return;
		}
	}
#endif
	fputs(buf, stdout);
}
