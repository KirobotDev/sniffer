#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <gdiplus.h>

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_BORDER_COLOR
#define DWMWA_BORDER_COLOR 34
#endif

#include "../core/sniffer_core.h"
#include "../core/sniffer_insight.h"
#include "../core/sniffer_winproc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

enum {
	ID_ADAPTER = 1001,
	ID_FLOW_LV = 1002,
	ID_PKT_LV  = 1003,
	ID_HEX     = 1004,
	ID_HOST_LV = 1005,
	ID_START   = 1006,
	ID_STOP    = 1007,
	ID_CLEAR   = 1008,
	ID_FILTER  = 1009,
	ID_APP_TREE  = 1010,
	ID_TRAY_SHOW = 1011,
	ID_TRAY_QUIT = 1012,
	ID_TOOLBAR_BG = 1013,
	ID_IFACE_BASE = 2100,
	WM_TRAY      = WM_USER + 50,
	ID_TRAY_ICON = 77,
	ID_TIMER       = 1,
	ID_TIMER_UI    = 2,
	INSIGHT_TICKS  = 10,
	STATUS_TICKS   = 4,
	PKT_BATCH      = 48,
};

#define GUI_PKT_CACHE 800
#define TOOLBAR_H    46
#define TOOLBAR_GAP  4
#define LOGO_SZ      38
#define BRAND_W      172
#define LEFT_W       400
#define TREE_LP_ALL  0
#define TREE_LP_APP(i) ((UINT)(i) + 1)
#define TREE_REFRESH_TICKS 25
#define STATUS_H     32
#define TITLE_H      26
#define MARGIN       12
#define GAP          10
#define PANEL_PAD    8
#define CARD_R       8

#define CLR_BG       RGB(30, 31, 34)
#define CLR_TOOLBAR  RGB(43, 45, 49)
#define CLR_CARD     RGB(49, 51, 56)
#define CLR_BORDER   RGB(32, 34, 38)
#define CLR_ROW      RGB(49, 51, 56)
#define CLR_ROW_ALT  RGB(44, 46, 51)
#define CLR_HEADER   RGB(57, 60, 66)
#define CLR_TEXT     RGB(242, 243, 245)
#define CLR_MUTED    RGB(181, 186, 193)
#define CLR_ACCENT   RGB(88, 101, 242)
#define CLR_IP       RGB(114, 137, 218)
#define CLR_GREEN    RGB(87, 242, 135)
#define CLR_SEL      RGB(58, 61, 67)
#define CLR_SEL_TXT  RGB(242, 243, 245)

static HWND g_hwnd, g_adapter, g_flow, g_pkt, g_hosts, g_hex, g_filter, g_status;
static HWND g_lbl_if, g_lbl_filt, g_app_tree;
static HWND g_hdr_hosts, g_hdr_flow, g_hdr_pkt, g_toolbar_bg;
static HFONT g_font, g_font_bold, g_font_sec;
static HBRUSH g_br_bg, g_br_card, g_br_edit, g_br_tool, g_br_header;
static sniffer_packet_t g_cache[GUI_PKT_CACHE];
static int g_cache_head;
static wchar_t g_filter_txt[160];
static int g_tick, g_ui_tick, g_sizing;
static uint64_t g_status_bytes;
static int g_status_pkts, g_status_flows, g_status_hosts;
static wchar_t g_status_cap[24];
static HINSTANCE g_hinst;
static NOTIFYICONDATAW g_tray;
static int g_tray_on;
static int g_apps_tree_sig;
static int g_tree_busy;
static ULONG_PTR g_gdiplus;
static HICON g_app_icon;
static int g_adapter_idx;
static RECT g_toolbar_iface_rc;
static WNDPROC g_toolbar_oldproc;
static WNDPROC g_lv_oldproc[3];
static int g_lv_hscroll[3];
static int g_lv_vscroll[3];
static int g_pkt_purge_rows;

#define LV_SLOT_HOSTS 0
#define LV_SLOT_FLOW  1
#define LV_SLOT_PKT   2

static int lv_slot_idx(HWND lv) {
	if (lv == g_hosts)
		return LV_SLOT_HOSTS;
	if (lv == g_flow)
		return LV_SLOT_FLOW;
	if (lv == g_pkt)
		return LV_SLOT_PKT;
	return -1;
}

static LRESULT CALLBACK lv_subclass_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
	int slot = lv_slot_idx(h);
	WNDPROC old = slot >= 0 ? g_lv_oldproc[slot] : NULL;
	LRESULT r = old ? CallWindowProcW(old, h, m, w, l) : DefWindowProcW(h, m, w, l);
	if (slot >= 0 &&
	    (m == WM_HSCROLL || m == WM_VSCROLL || m == WM_MOUSEWHEEL || m == WM_MOUSEHWHEEL)) {
		g_lv_hscroll[slot] = GetScrollPos(h, SB_HORZ);
		g_lv_vscroll[slot] = GetScrollPos(h, SB_VERT);
	}
	return r;
}

static void lv_hook_scroll(HWND lv, int slot) {
	g_lv_oldproc[slot] = (WNDPROC)SetWindowLongPtrW(lv, GWLP_WNDPROC, (LONG_PTR)lv_subclass_proc);
}

static void lv_scroll_apply(HWND lv, int slot, int top, int hx, int vy) {
	int n = ListView_GetItemCount(lv);
	if (n <= 0)
		return;
	if (top >= n)
		top = n - 1;
	if (top > 0) {
		RECT r0, rt;
		if (ListView_GetItemRect(lv, 0, &r0, LVIR_BOUNDS) && ListView_GetItemRect(lv, top, &rt, LVIR_BOUNDS)) {
			int dy = rt.top - r0.top;
			if (dy > 0)
				SendMessageW(lv, LVM_SCROLL, 0, (LPARAM)dy);
		}
	}
	if (hx > 0) {
		SCROLLINFO si = {sizeof(si), SIF_POS};
		si.nPos = hx;
		SetScrollInfo(lv, SB_HORZ, &si, TRUE);
		SendMessageW(lv, WM_HSCROLL, MAKEWPARAM(SB_THUMBPOSITION, hx), 0);
		SendMessageW(lv, LVM_SCROLL, (WPARAM)hx, 0);
	}
	if (vy > 0) {
		SCROLLINFO si = {sizeof(si), SIF_POS};
		si.nPos = vy;
		SetScrollInfo(lv, SB_VERT, &si, TRUE);
		SendMessageW(lv, WM_VSCROLL, MAKEWPARAM(SB_THUMBPOSITION, vy), 0);
	}
	g_lv_hscroll[slot] = hx;
	g_lv_vscroll[slot] = vy;
}

static void ui_raise(void);
static int logo_resolve_path(wchar_t *out, size_t n);
static int logo_load(HINSTANCE inst);
static void logo_unload(void);
static void draw_toolbar_brand(HDC hdc);
static void tray_show(HWND hwnd);
static void tray_hide(void);
static void tray_quit(HWND hwnd);
static void lv_freeze(HWND lv, BOOL freeze);
static void refresh_insight_lists(void);

static void acp_to_wide(const char *in, wchar_t *out, size_t n) {
	MultiByteToWideChar(CP_ACP, 0, in ? in : "", -1, out, (int)n);
}

static void format_bytes(uint64_t b, wchar_t *out, size_t n) {
	if (b < 1024)
		swprintf(out, n, L"%llu o", (unsigned long long)b);
	else if (b < 1024 * 1024)
		swprintf(out, n, L"%.1f Ko", b / 1024.0);
	else
		swprintf(out, n, L"%.2f Mo", b / (1024.0 * 1024.0));
}

static int logo_resolve_path(wchar_t *out, size_t n) {
	wchar_t exe[MAX_PATH];
	if (GetModuleFileNameW(g_hinst ? g_hinst : NULL, exe, MAX_PATH) == 0)
		return 0;
	wchar_t dir[MAX_PATH];
	wcsncpy(dir, exe, MAX_PATH);
	dir[MAX_PATH - 1] = 0;
	wchar_t *slash = wcsrchr(dir, L'\\');
	if (slash)
		*slash = 0;
	static const wchar_t *suffix[] = {L"\\image\\logo.jpg", L"\\..\\image\\logo.jpg",
	                                  L"\\..\\..\\image\\logo.jpg"};
	for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++) {
		_snwprintf(out, n, L"%s%s", dir, suffix[i]);
		out[n - 1] = 0;
		if (GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES)
			return 1;
	}
	return 0;
}

static int logo_load(HINSTANCE inst) {
	g_hinst = inst;
	if (!g_gdiplus) {
		GdiplusStartupInput gi = {1};
		if (GdiplusStartup(&g_gdiplus, &gi, NULL) != Ok)
			return 0;
	}
	wchar_t path[MAX_PATH];
	if (!logo_resolve_path(path, MAX_PATH))
		return 0;
	GpBitmap *bmp = NULL;
	if (GdipCreateBitmapFromFile(path, &bmp) != Ok)
		return 0;
	HICON icon = NULL;
	if (GdipCreateHICONFromBitmap(bmp, &icon) == Ok && icon)
		g_app_icon = icon;
	GdipDisposeImage(bmp);
	return g_app_icon != NULL;
}

static void logo_unload(void) {
	if (g_app_icon) {
		DestroyIcon(g_app_icon);
		g_app_icon = NULL;
	}
	if (g_gdiplus) {
		GdiplusShutdown(g_gdiplus);
		g_gdiplus = 0;
	}
}

static void draw_toolbar_brand(HDC hdc) {
	int y = (TOOLBAR_H - LOGO_SZ) / 2;
	if (y < 4)
		y = 4;
	if (g_app_icon)
		DrawIconEx(hdc, MARGIN, y, g_app_icon, LOGO_SZ, LOGO_SZ, 0, NULL, DI_NORMAL);
	SetBkMode(hdc, TRANSPARENT);
	SetTextColor(hdc, CLR_TEXT);
	SelectObject(hdc, g_font_bold);
	int ty = (TOOLBAR_H - 18) / 2;
	TextOutW(hdc, MARGIN + LOGO_SZ + 10, ty, L"Sniffer", 7);
}

static void adapter_update_label(wchar_t *out, size_t n) {
	char name[SNIFFER_DEV_NAME_LEN], desc[SNIFFER_DEV_DESC_LEN];
	int i = g_adapter_idx;
	if (i < 0)
		i = 0;
	if (sniffer_device_count() > 0)
		sniffer_device_get(i, name, sizeof(name), desc, sizeof(desc));
	else {
		desc[0] = 0;
		strcpy(name, "?");
	}
	wchar_t wdesc[220];
	acp_to_wide(desc[0] ? desc : name, wdesc, 220);
	swprintf(out, n, L"%s  ▾", wdesc);
}

static void draw_toolbar_iface(HDC hdc, int win_w) {
	wchar_t line[260];
	adapter_update_label(line, 260);
	SetBkMode(hdc, TRANSPARENT);
	SetTextColor(hdc, CLR_MUTED);
	SelectObject(hdc, g_font);
	g_toolbar_iface_rc.left = win_w - MARGIN - 480;
	g_toolbar_iface_rc.top = 0;
	g_toolbar_iface_rc.right = win_w - MARGIN;
	g_toolbar_iface_rc.bottom = TOOLBAR_H;
	DrawTextW(hdc, line, -1, &g_toolbar_iface_rc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}

static void show_iface_menu(HWND hwnd) {
	int n = sniffer_device_count();
	if (n <= 0)
		return;
	HMENU menu = CreatePopupMenu();
	for (int i = 0; i < n && i < 48; i++) {
		char name[SNIFFER_DEV_NAME_LEN], desc[SNIFFER_DEV_DESC_LEN];
		sniffer_device_get(i, name, sizeof(name), desc, sizeof(desc));
		wchar_t line[320];
		acp_to_wide(desc[0] ? desc : name, line, 320);
		UINT flags = MF_STRING;
		if (i == g_adapter_idx)
			flags |= MF_CHECKED;
		AppendMenuW(menu, flags, ID_IFACE_BASE + i, line);
	}
	POINT pt = {g_toolbar_iface_rc.right, g_toolbar_iface_rc.bottom};
	ClientToScreen(hwnd, &pt);
	SetForegroundWindow(hwnd);
	TrackPopupMenu(menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, NULL);
	DestroyMenu(menu);
}

static LRESULT CALLBACK toolbar_bg_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
	if (m == WM_LBUTTONUP) {
		POINT pt = {(SHORT)LOWORD(l), (SHORT)HIWORD(l)};
		MapWindowPoints(h, g_hwnd, &pt, 1);
		if (PtInRect(&g_toolbar_iface_rc, pt)) {
			show_iface_menu(g_hwnd);
			return 0;
		}
	}
	return CallWindowProcW(g_toolbar_oldproc, h, m, w, l);
}

static void apply_window_chrome(HWND hwnd) {
	BOOL dark = TRUE;
	DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
	COLORREF border = CLR_CARD;
	DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border, sizeof(border));
}

static void style_dark_combo(HWND cb) {
	SetWindowTheme(cb, L"DarkMode_CFD", L"Explorer");
}

static void style_dark_button(HWND btn) {
	SetWindowTheme(btn, L"DarkMode_Explorer", NULL);
}

static void style_flat_field(HWND w) {
	LONG st = GetWindowLongW(w, GWL_STYLE);
	st &= ~WS_BORDER;
	SetWindowLongW(w, GWL_STYLE, st);
	SetWindowPos(w, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
}

static void style_dark_listview(HWND lv) {
	SetWindowTheme(lv, L"DarkMode_Explorer", NULL);
	ListView_SetBkColor(lv, CLR_ROW);
	ListView_SetTextBkColor(lv, CLR_ROW);
	ListView_SetTextColor(lv, CLR_TEXT);
	ListView_SetExtendedListViewStyle(lv,
	                                  LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
	SendMessageW(lv, CCM_SETVERSION, COMCTL32_VERSION, 0);
	LONG st = GetWindowLongW(lv, GWL_STYLE);
	st &= ~(WS_BORDER | WS_DLGFRAME);
	SetWindowLongW(lv, GWL_STYLE, st);
	LONG ex = GetWindowLongW(lv, GWL_EXSTYLE);
	ex &= ~(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE);
	SetWindowLongW(lv, GWL_EXSTYLE, ex);
	SetWindowPos(lv, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
	HWND hdr = ListView_GetHeader(lv);
	if (hdr) {
		SetWindowTheme(hdr, L"DarkMode_Explorer", NULL);
		SendMessageW(hdr, WM_SETFONT, (WPARAM)g_font_bold, TRUE);
		ex = GetWindowLongW(hdr, GWL_EXSTYLE);
		ex &= ~(WS_EX_CLIENTEDGE);
		SetWindowLongW(hdr, GWL_EXSTYLE, ex);
	}
}

static int is_list_hdr(HWND who) {
	return who == ListView_GetHeader(g_hosts) || who == ListView_GetHeader(g_flow) ||
	       who == ListView_GetHeader(g_pkt);
}

static LRESULT on_hdr_customdraw(LPNMCUSTOMDRAW cd) {
	switch (cd->dwDrawStage) {
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW;
	case CDDS_ITEMPREPAINT:
		SetBkColor(cd->hdc, CLR_HEADER);
		SetTextColor(cd->hdc, CLR_MUTED);
		SelectObject(cd->hdc, g_font_bold);
		return CDRF_DODEFAULT;
	}
	return CDRF_DODEFAULT;
}

static void resize_flow_columns(int list_w) {
	int arrow = 28, ports = 56, proto = 52, traf = 76, cnt = 44, pad = 24;
	int fixed = ports + arrow + ports + proto + traf + cnt + pad;
	int rest = list_w - fixed;
	if (rest < 280)
		rest = 280;
	int ipw = rest / 2;
	int det = rest - ipw;
	ListView_SetColumnWidth(g_flow, 0, ipw);
	ListView_SetColumnWidth(g_flow, 1, ports);
	ListView_SetColumnWidth(g_flow, 2, arrow);
	ListView_SetColumnWidth(g_flow, 3, ipw);
	ListView_SetColumnWidth(g_flow, 4, ports);
	ListView_SetColumnWidth(g_flow, 5, proto);
	ListView_SetColumnWidth(g_flow, 6, traf);
	ListView_SetColumnWidth(g_flow, 7, cnt);
	ListView_SetColumnWidth(g_flow, 8, det > 80 ? det : 80);
}

static void resize_host_columns(int list_w) {
	ListView_SetColumnWidth(g_hosts, 0, 112);
	ListView_SetColumnWidth(g_hosts, 1, 76);
	ListView_SetColumnWidth(g_hosts, 2, 76);
	ListView_SetColumnWidth(g_hosts, 3, 40);
	ListView_SetColumnWidth(g_hosts, 4, list_w - 314 > 72 ? list_w - 314 : 72);
}

static void resize_pkt_columns(int list_w) {
	int fixed = 58 + 52 + 56;
	int pair = (list_w - fixed - 24) / 2;
	if (pair < 120)
		pair = 120;
	int info = list_w - 2 * pair - fixed;
	if (info < 100)
		info = 100;
	ListView_SetColumnWidth(g_pkt, 0, pair);
	ListView_SetColumnWidth(g_pkt, 1, pair);
	ListView_SetColumnWidth(g_pkt, 2, 58);
	ListView_SetColumnWidth(g_pkt, 3, info);
	ListView_SetColumnWidth(g_pkt, 4, 52);
}

static void add_col(HWND lv, int i, const wchar_t *t, int w) {
	LVCOLUMNW c = {0};
	c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	c.pszText = (wchar_t *)t;
	c.cx = w;
	c.iSubItem = i;
	ListView_InsertColumn(lv, i, &c);
}

static int pass_filter_ips(const char *a, const char *b, const char *extra) {
	if (!g_filter_txt[0])
		return 1;
	wchar_t wa[64], wb[64], wx[200];
	acp_to_wide(a, wa, 64);
	acp_to_wide(b, wb, 64);
	acp_to_wide(extra ? extra : "", wx, 200);
	return wcsstr(wa, g_filter_txt) || wcsstr(wb, g_filter_txt) || wcsstr(wx, g_filter_txt);
}

static int apps_tree_signature(void) {
	int n = sniffer_proc_app_count();
	int sig = n * 997;
	for (int i = 0; i < n; i++) {
		char exe[72];
		if (sniffer_proc_app_get(i, exe, sizeof(exe), NULL) != 0)
			continue;
		for (int k = 0; exe[k]; k++)
			sig = sig * 31 + (unsigned char)exe[k];
	}
	return sig;
}

static HTREEITEM tree_insert_app(const wchar_t *text, LPARAM lp) {
	TVINSERTSTRUCT ins = {0};
	ins.hParent = TVI_ROOT;
	ins.hInsertAfter = TVI_LAST;
	ins.item.mask = TVIF_TEXT | TVIF_PARAM;
	ins.item.lParam = lp;
	ins.item.pszText = (wchar_t *)text;
	return TreeView_InsertItem(g_app_tree, &ins);
}

static void tree_restore_select(LPARAM want) {
	HTREEITEM it = TreeView_GetRoot(g_app_tree);
	while (it) {
		TVITEM tv = {0};
		tv.mask = TVIF_PARAM;
		tv.hItem = it;
		if (TreeView_GetItem(g_app_tree, &tv) && tv.lParam == want) {
			TreeView_SelectItem(g_app_tree, it);
			return;
		}
		it = TreeView_GetNextSibling(g_app_tree, it);
	}
	TreeView_SelectItem(g_app_tree, TreeView_GetRoot(g_app_tree));
}

static void fill_app_tree(void) {
	const char *filt = sniffer_proc_filter_exe();
	LPARAM want = TREE_LP_ALL;
	if (filt[0]) {
		int n = sniffer_proc_app_count();
		for (int i = 0; i < n; i++) {
			char exe[72];
			if (sniffer_proc_app_get(i, exe, sizeof(exe), NULL) == 0 && _stricmp(exe, filt) == 0) {
				want = TREE_LP_APP(i);
				break;
			}
		}
	}

	LPARAM vis_lp = 0;
	HTREEITEM vis =
	    (HTREEITEM)SendMessageW(g_app_tree, TVM_GETNEXTITEM, TVGN_FIRSTVISIBLE, 0);
	if (vis) {
		TVITEM vtx = {0};
		vtx.mask = TVIF_PARAM;
		vtx.hItem = vis;
		if (TreeView_GetItem(g_app_tree, &vtx))
			vis_lp = vtx.lParam;
	}

	g_tree_busy = 1;
	SendMessageW(g_app_tree, WM_SETREDRAW, FALSE, 0);
	TreeView_DeleteAllItems(g_app_tree);
	tree_insert_app(L"Toutes les applications", TREE_LP_ALL);
	int n = sniffer_proc_app_count();
	for (int i = 0; i < n; i++) {
		char exe[72];
		int conn = 0;
		if (sniffer_proc_app_get(i, exe, sizeof(exe), &conn) != 0)
			continue;
		wchar_t wexe[80], line[160];
		acp_to_wide(exe, wexe, 80);
		swprintf(line, 160, L"%s  (%d conn.)", wexe, conn);
		tree_insert_app(line, TREE_LP_APP(i));
	}
	if (n == 0)
		tree_insert_app(L"(Discord, Brave… — génère du trafic)", 0);
	tree_restore_select(want);
	if (vis_lp) {
		HTREEITEM it = TreeView_GetRoot(g_app_tree);
		while (it) {
			TVITEM tv = {0};
			tv.mask = TVIF_PARAM;
			tv.hItem = it;
			if (TreeView_GetItem(g_app_tree, &tv) && tv.lParam == vis_lp) {
				SendMessageW(g_app_tree, TVM_ENSUREVISIBLE, 0, (LPARAM)it);
				break;
			}
			it = TreeView_GetNextSibling(g_app_tree, it);
		}
	}
	SendMessageW(g_app_tree, WM_SETREDRAW, TRUE, 0);
	InvalidateRect(g_app_tree, NULL, FALSE);
	g_apps_tree_sig = apps_tree_signature();
	g_tree_busy = 0;
}

static void fill_app_tree_if_changed(void) {
	if ((g_ui_tick % TREE_REFRESH_TICKS) != 0)
		return;
	int sig = apps_tree_signature();
	if (sig != g_apps_tree_sig)
		fill_app_tree();
}

static void on_app_tree_select(LPARAM lp) {
	if (lp == TREE_LP_ALL || lp == 0)
		sniffer_proc_set_filter_exe("");
	else if (lp > 0 && lp <= 256) {
		char exe[72];
		int conn;
		if (sniffer_proc_app_get((int)lp - 1, exe, sizeof(exe), &conn) == 0)
			sniffer_proc_set_filter_exe(exe);
	}
	refresh_insight_lists();
}

static void tray_show(HWND hwnd) {
	if (g_tray_on)
		return;
	ZeroMemory(&g_tray, sizeof(g_tray));
	g_tray.cbSize = sizeof(g_tray);
	g_tray.hWnd = hwnd;
	g_tray.uID = ID_TRAY_ICON;
	g_tray.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
	g_tray.uCallbackMessage = WM_TRAY;
	g_tray.hIcon = g_app_icon ? g_app_icon : LoadIconW(NULL, IDI_APPLICATION);
	wcscpy(g_tray.szTip, L"Sniffer — capture active (double-clic pour ouvrir)");
	Shell_NotifyIconW(NIM_ADD, &g_tray);
	g_tray_on = 1;
}

static void tray_hide(void) {
	if (g_tray_on) {
		Shell_NotifyIconW(NIM_DELETE, &g_tray);
		g_tray_on = 0;
	}
}

static void tray_quit(HWND hwnd) {
	tray_hide();
	DestroyWindow(hwnd);
}


static int pass_flow(const sniffer_flow_t *f) {
	return pass_filter_ips(f->ip_a, f->ip_b, f->hint) && sniffer_proc_flow_matches(f);
}

static int pass_host(const sniffer_host_t *h) {
	return pass_filter_ips(h->ip, h->ip, h->alias) && sniffer_proc_host_matches(h);
}

static int pass_pkt(const sniffer_packet_t *pkt) {
	return pass_filter_ips(pkt->src, pkt->dst, pkt->info) && sniffer_proc_pkt_matches(pkt);
}

static int pick_adapter_index(void) {
	int n = sniffer_device_count();
	if (n <= 0)
		return 0;
	return sniffer_device_default_index();
}

static void init_adapter_index(void) {
	g_adapter_idx = pick_adapter_index();
	if (g_adapter_idx < 0)
		g_adapter_idx = 0;
}

static int cmp_flow_bytes(const void *a, const void *b) {
	int ia = *(const int *)a, ib = *(const int *)b;
	sniffer_flow_t fa, fb;
	if (sniffer_insight_flow_get(ia, &fa) || sniffer_insight_flow_get(ib, &fb))
		return 0;
	if (fb.bytes > fa.bytes)
		return 1;
	if (fb.bytes < fa.bytes)
		return -1;
	return 0;
}

static void lv_freeze(HWND lv, BOOL freeze) {
	SendMessageW(lv, WM_SETREDRAW, freeze ? FALSE : TRUE, 0);
}

typedef struct {
	int top;
	int scroll_x;
	int scroll_y;
	int slot;
} lv_scrollsnap;

static void lv_snap_view(HWND lv, lv_scrollsnap *s) {
	memset(s, 0, sizeof(*s));
	s->slot = lv_slot_idx(lv);
	s->top = ListView_GetTopIndex(lv);
	if (s->slot >= 0) {
		s->scroll_x = g_lv_hscroll[s->slot];
		s->scroll_y = g_lv_vscroll[s->slot];
	}
	if (s->scroll_x <= 0)
		s->scroll_x = GetScrollPos(lv, SB_HORZ);
	if (s->scroll_y <= 0)
		s->scroll_y = GetScrollPos(lv, SB_VERT);
}

static void lv_restore_view(HWND lv, const lv_scrollsnap *s) {
	int slot = s->slot >= 0 ? s->slot : lv_slot_idx(lv);
	int top = s->top;
	if (g_pkt_purge_rows > 0 && slot == LV_SLOT_PKT && top > 0) {
		top -= g_pkt_purge_rows;
		if (top < 0)
			top = 0;
	}
	lv_scroll_apply(lv, slot >= 0 ? slot : 0, top, s->scroll_x, s->scroll_y);
}

static void refresh_flows(void) {
	ListView_DeleteAllItems(g_flow);
	int n = sniffer_insight_flow_count();
	if (n <= 0)
		return;
	int order[2048];
	if (n > 2048)
		n = 2048;
	for (int i = 0; i < n; i++)
		order[i] = i;
	qsort(order, (size_t)n, sizeof(order[0]), cmp_flow_bytes);
	int shown = 0;
	for (int oi = 0; oi < n && shown < 600; oi++) {
		sniffer_flow_t f;
		if (sniffer_insight_flow_get(order[oi], &f) != 0)
			continue;
		if (!pass_flow(&f))
			continue;
		wchar_t ipa[48], ipb[48], pa[8], pb[8], pr[8], tr[24], pk[16], hint[140];
		acp_to_wide(f.ip_a, ipa, 48);
		acp_to_wide(f.ip_b, ipb, 48);
		swprintf(pa, 8, L"%u", f.port_a);
		swprintf(pb, 8, L"%u", f.port_b);
		acp_to_wide(f.proto, pr, 8);
		format_bytes(f.bytes, tr, 24);
		swprintf(pk, 16, L"%llu", (unsigned long long)f.packets);
		acp_to_wide(f.hint, hint, 140);
		int row = ListView_GetItemCount(g_flow);
		LVITEMW it = {0};
		it.mask = LVIF_TEXT;
		it.iItem = row;
		it.pszText = ipa;
		ListView_InsertItem(g_flow, &it);
		ListView_SetItemText(g_flow, row, 1, pa);
		ListView_SetItemText(g_flow, row, 2, L"→");
		ListView_SetItemText(g_flow, row, 3, ipb);
		ListView_SetItemText(g_flow, row, 4, pb);
		ListView_SetItemText(g_flow, row, 5, pr);
		ListView_SetItemText(g_flow, row, 6, tr);
		ListView_SetItemText(g_flow, row, 7, pk);
		ListView_SetItemText(g_flow, row, 8, hint);
		shown++;
	}
}

static int cmp_host_traffic(const void *a, const void *b) {
	int ia = *(const int *)a, ib = *(const int *)b;
	sniffer_host_t ha, hb;
	if (sniffer_insight_host_get(ia, &ha) || sniffer_insight_host_get(ib, &hb))
		return 0;
	uint64_t ta = ha.bytes_tx + ha.bytes_rx, tb = hb.bytes_tx + hb.bytes_rx;
	if (tb > ta)
		return 1;
	if (tb < ta)
		return -1;
	return 0;
}

static void refresh_hosts(void) {
	ListView_DeleteAllItems(g_hosts);
	int n = sniffer_insight_host_count();
	if (n <= 0)
		return;
	int order[512];
	if (n > 512)
		n = 512;
	for (int i = 0; i < n; i++)
		order[i] = i;
	qsort(order, (size_t)n, sizeof(order[0]), cmp_host_traffic);
	int shown = 0;
	for (int oi = 0; oi < n && shown < 200; oi++) {
		sniffer_host_t h;
		if (sniffer_insight_host_get(order[oi], &h) != 0)
			continue;
		if (!pass_host(&h))
			continue;
		wchar_t ip[48], tx[24], rx[24], pk[16], note[180];
		acp_to_wide(h.ip, ip, 48);
		format_bytes(h.bytes_tx, tx, 24);
		format_bytes(h.bytes_rx, rx, 24);
		swprintf(pk, 16, L"%llu", (unsigned long long)h.packets);
		if (h.alias[0])
			acp_to_wide(h.alias, note, 180);
		else if (h.is_console)
			wcscpy(note, L"Console / Jeu");
		else
			wcscpy(note, L"—");
		int row = ListView_GetItemCount(g_hosts);
		LVITEMW it = {0};
		it.mask = LVIF_TEXT;
		it.iItem = row;
		it.pszText = ip;
		ListView_InsertItem(g_hosts, &it);
		ListView_SetItemText(g_hosts, row, 1, tx);
		ListView_SetItemText(g_hosts, row, 2, rx);
		ListView_SetItemText(g_hosts, row, 3, pk);
		ListView_SetItemText(g_hosts, row, 4, note);
		shown++;
	}
}

static int cache_push(const sniffer_packet_t *p) {
	int slot = g_cache_head % GUI_PKT_CACHE;
	g_cache[slot] = *p;
	return g_cache_head++;
}

static void add_packet_row(const sniffer_packet_t *pkt, int slot) {
	if (!pass_pkt(pkt))
		return;
	wchar_t wsrc[80], wdst[80], wsp[12], wdp[12], wproto[12], winfo[240], wlen[16];
	{
		wchar_t ips[48], ipd[48];
		acp_to_wide(pkt->src, ips, 48);
		acp_to_wide(pkt->dst, ipd, 48);
		if (pkt->sport)
			swprintf(wsrc, 80, L"%s:%u", ips, pkt->sport);
		else
			wcscpy(wsrc, ips);
		if (pkt->dport)
			swprintf(wdst, 80, L"%s:%u", ipd, pkt->dport);
		else
			wcscpy(wdst, ipd);
	}
	acp_to_wide(sniffer_proto_name(pkt->l4 != SNIFFER_PROTO_OTHER ? pkt->l4 : pkt->l3), wproto, 12);
	acp_to_wide(pkt->info, winfo, 240);
	swprintf(wlen, 16, L"%u", pkt->caplen);
	int row = ListView_GetItemCount(g_pkt);
	LVITEMW it = {0};
	it.mask = LVIF_TEXT | LVIF_PARAM;
	it.iItem = row;
	it.pszText = wsrc;
	it.lParam = slot;
	ListView_InsertItem(g_pkt, &it);
	ListView_SetItemText(g_pkt, row, 1, wdst);
	ListView_SetItemText(g_pkt, row, 2, wproto);
	ListView_SetItemText(g_pkt, row, 3, winfo);
	ListView_SetItemText(g_pkt, row, 4, wlen);
	while (ListView_GetItemCount(g_pkt) > 1500) {
		ListView_DeleteItem(g_pkt, 0);
		g_pkt_purge_rows++;
	}
}

static void refresh_insight_lists(void) {
	lv_scrollsnap flow_snap, host_snap;
	lv_snap_view(g_flow, &flow_snap);
	lv_snap_view(g_hosts, &host_snap);
	lv_freeze(g_flow, TRUE);
	lv_freeze(g_hosts, TRUE);
	refresh_flows();
	refresh_hosts();
	lv_freeze(g_flow, FALSE);
	lv_freeze(g_hosts, FALSE);
	lv_restore_view(g_flow, &flow_snap);
	lv_restore_view(g_hosts, &host_snap);
	RedrawWindow(g_flow, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
	RedrawWindow(g_hosts, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
}

static void poll_packets(void) {
	int added = 0;
	lv_scrollsnap pkt_snap;
	g_pkt_purge_rows = 0;
	if (!g_sizing)
		lv_snap_view(g_pkt, &pkt_snap);
	if (!g_sizing)
		lv_freeze(g_pkt, TRUE);
	for (int k = 0; k < PKT_BATCH; k++) {
		sniffer_packet_t pkt;
		if (!sniffer_poll(&pkt))
			break;
		int slot = cache_push(&pkt);
		add_packet_row(&pkt, slot);
		added++;
	}
	if (!g_sizing) {
		lv_restore_view(g_pkt, &pkt_snap);
		lv_freeze(g_pkt, FALSE);
		if (added > 0)
			RedrawWindow(g_pkt, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
	}
	g_tick++;
}

static void on_ui_timer(void) {
	if (g_sizing)
		return;
	g_ui_tick++;
	sniffer_proc_refresh();
	fill_app_tree_if_changed();
	if ((g_ui_tick % INSIGHT_TICKS) != 0)
		return;
	refresh_insight_lists();
}

static void relayout(void) {
	RECT rc;
	GetClientRect(g_hwnd, &rc);
	int w = rc.right, h = rc.bottom;
	if (w < 640 || h < 400)
		return;

	MoveWindow(g_toolbar_bg, 0, 0, w, TOOLBAR_H, TRUE);
	SetWindowPos(g_toolbar_bg, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

	MoveWindow(g_lbl_if, MARGIN, 18, 0, 0, TRUE);
	ShowWindow(g_lbl_if, SW_HIDE);
	ShowWindow(g_adapter, SW_HIDE);
	ShowWindow(g_lbl_filt, SW_HIDE);
	ShowWindow(g_filter, SW_HIDE);
	MoveWindow(g_status, MARGIN + 4, h - STATUS_H, w - 2 * MARGIN - 8, STATUS_H, TRUE);

	int bottom = h - STATUS_H - MARGIN - 4;
	int rx = MARGIN + LEFT_W + GAP;
	int rw = w - rx - MARGIN;
	int ly = TOOLBAR_H + TOOLBAR_GAP;
	int lh = bottom - ly;

	ShowWindow(g_hdr_hosts, SW_HIDE);
	int list_inset = PANEL_PAD + TITLE_H;
	int tree_block = lh * 44 / 100;
	if (tree_block < 200)
		tree_block = 200;
	MoveWindow(g_app_tree, MARGIN + PANEL_PAD, ly + list_inset, LEFT_W - 2 * PANEL_PAD,
	           tree_block - list_inset - PANEL_PAD, TRUE);
	int hy = ly + tree_block + GAP;
	int host_h = lh - tree_block - GAP;
	MoveWindow(g_hosts, MARGIN + PANEL_PAD, hy + list_inset, LEFT_W - 2 * PANEL_PAD,
	           host_h - list_inset - PANEL_PAD, TRUE);

	int ry = ly;
	int inner_h = lh;
	int flow_block = inner_h * 58 / 100;
	if (flow_block < 120)
		flow_block = 120;
	int pkt_block = inner_h - flow_block - GAP;
	if (pkt_block < 100)
		pkt_block = 100;

	ShowWindow(g_hdr_flow, SW_HIDE);
	ShowWindow(g_hdr_pkt, SW_HIDE);
	int flow_y = ry + list_inset;
	int flow_h = flow_block - list_inset - PANEL_PAD;
	MoveWindow(g_flow, rx + PANEL_PAD, flow_y, rw - 2 * PANEL_PAD, flow_h, TRUE);

	int pkt_y = ry + flow_block + GAP;
	int pkt_list_y = pkt_y + list_inset;
	int pkt_h = pkt_block - list_inset - PANEL_PAD;
	MoveWindow(g_pkt, rx + PANEL_PAD, pkt_list_y, rw - 2 * PANEL_PAD, pkt_h, TRUE);
	ShowWindow(g_hex, SW_HIDE);

	int host_w = LEFT_W - 2 * PANEL_PAD;
	int list_w = rw - 2 * PANEL_PAD;
	resize_host_columns(host_w);
	resize_flow_columns(list_w);
	resize_pkt_columns(list_w);
	if (!g_sizing)
		ui_raise();
}

static void panel_rect(int x, int y, int w, int h, RECT *out) {
	out->left = x;
	out->top = y;
	out->right = x + w;
	out->bottom = y + h;
}

static void ui_raise(void) {
	HWND *back = (HWND[]){g_toolbar_bg};
	for (size_t i = 0; i < 1; i++)
		SetWindowPos(back[i], HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	HWND *mid = (HWND[]){g_app_tree, g_hosts, g_flow, g_pkt, g_status};
	for (size_t i = 0; i < 5; i++)
		SetWindowPos(mid[i], HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	HWND *front = (HWND[]){g_lbl_if};
	for (size_t i = 0; i < 1; i++)
		BringWindowToTop(front[i]);
}

static void draw_round_card(HDC hdc, const RECT *box) {
	HBRUSH fill = CreateSolidBrush(CLR_CARD);
	HPEN edge = CreatePen(PS_SOLID, 1, CLR_BORDER);
	HGDIOBJ of = SelectObject(hdc, fill);
	HGDIOBJ op = SelectObject(hdc, edge);
	RoundRect(hdc, box->left, box->top, box->right, box->bottom, CARD_R, CARD_R);
	SelectObject(hdc, op);
	SelectObject(hdc, of);
	DeleteObject(edge);
	DeleteObject(fill);
}

static void draw_card_title(HDC hdc, const RECT *card, const wchar_t *title) {
	RECT tr = {card->left + PANEL_PAD + 2, card->top + 4, card->right - PANEL_PAD,
	           card->top + TITLE_H};
	SetBkMode(hdc, TRANSPARENT);
	SetTextColor(hdc, CLR_MUTED);
	SelectObject(hdc, g_font_sec);
	DrawTextW(hdc, title, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}

static void paint_chrome(HWND hwnd) {
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hwnd, &ps);
	RECT rc, box, tb;
	GetClientRect(hwnd, &rc);
	int w = rc.right, h = rc.bottom;
	int bottom = h - STATUS_H - MARGIN;
	int rx = MARGIN + LEFT_W + GAP;
	int rw = w - rx - MARGIN;
	int ly = TOOLBAR_H + TOOLBAR_GAP;
	int lh = bottom - ly;
	int flow_block = lh * 58 / 100;
	if (flow_block < 120)
		flow_block = 120;
	int pkt_y = ly + flow_block + GAP;
	int pkt_block = lh - flow_block - GAP;

	FillRect(hdc, &rc, g_br_bg);
	tb.left = 0;
	tb.top = 0;
	tb.right = w;
	tb.bottom = TOOLBAR_H;
	FillRect(hdc, &tb, g_br_bg);
	draw_toolbar_brand(hdc);
	draw_toolbar_iface(hdc, w);

	int tree_block = lh * 44 / 100;
	if (tree_block < 200)
		tree_block = 200;
	panel_rect(MARGIN, ly, LEFT_W, tree_block, &box);
	draw_round_card(hdc, &box);
	draw_card_title(hdc, &box, L"Applications");
	panel_rect(MARGIN, ly + tree_block + GAP, LEFT_W, lh - tree_block - GAP, &box);
	draw_round_card(hdc, &box);
	draw_card_title(hdc, &box, L"Adresses IP actives");
	panel_rect(rx, ly, rw, flow_block, &box);
	draw_round_card(hdc, &box);
	draw_card_title(hdc, &box, L"Connexions");
	panel_rect(rx, pkt_y, rw, pkt_block, &box);
	draw_round_card(hdc, &box);
	draw_card_title(hdc, &box, L"Paquets en direct");
	EndPaint(hwnd, &ps);
}

static void on_start(void) {
	sniffer_stop();
	int i = g_adapter_idx;
	if (i < 0)
		i = 0;
	char name[SNIFFER_DEV_NAME_LEN], desc[SNIFFER_DEV_DESC_LEN];
	sniffer_device_get(i, name, sizeof(name), desc, sizeof(desc));
	sniffer_start(name, NULL);
	if (g_hwnd)
		InvalidateRect(g_hwnd, NULL, FALSE);
}

static void create_ui(HWND parent) {
	RECT rc;
	GetClientRect(parent, &rc);
	int w = rc.right, h = rc.bottom;

	g_toolbar_bg = CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE, 0, 0, w, TOOLBAR_H,
	                               parent, (HMENU)ID_TOOLBAR_BG, NULL, NULL);

	g_lbl_if = CreateWindowExW(0, L"STATIC", L"Interface réseau", WS_CHILD | WS_VISIBLE, 12, 14, 90,
	                           22, parent, NULL, NULL, NULL);
	g_adapter = CreateWindowExW(0, WC_COMBOBOXW, NULL, CBS_DROPDOWNLIST | WS_CHILD, 0, 0, 0, 0,
	                            parent, (HMENU)ID_ADAPTER, NULL, NULL);

	g_lbl_filt = CreateWindowExW(0, L"STATIC", L"Filtre IP", WS_CHILD, 500, 48, 80, 18, parent, NULL,
	                             NULL, NULL);
	g_app_tree = CreateWindowExW(0, WC_TREEVIEWW, NULL,
	                             WS_CHILD | WS_VISIBLE | TVS_SHOWSELALWAYS | TVS_FULLROWSELECT,
	                             12, 120, 360, 200, parent, (HMENU)ID_APP_TREE, NULL, NULL);
	g_filter = CreateWindowExW(0, L"EDIT", NULL, WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, parent,
	                           (HMENU)ID_FILTER, NULL, NULL);

	g_hdr_hosts = CreateWindowExW(0, L"STATIC", L"  Adresses IP actives", WS_CHILD | WS_VISIBLE,
	                              12, 56, 320, 20, parent, NULL, NULL, NULL);
	g_hosts = CreateWindowExW(0, WC_LISTVIEWW, NULL,
	                          WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
	                          12, 78, 320, 300, parent, (HMENU)ID_HOST_LV, NULL, NULL);
	add_col(g_hosts, 0, L"Adresse IP", 118);
	add_col(g_hosts, 1, L"↑ Envoyé", 72);
	add_col(g_hosts, 2, L"↓ Reçu", 72);
	add_col(g_hosts, 3, L"#", 40);
	add_col(g_hosts, 4, L"Info", 120);

	g_hdr_flow = CreateWindowExW(0, L"STATIC", L"  Connexions (IP → IP)", WS_CHILD | WS_VISIBLE, 360,
	                             56, 400, 20, parent, NULL, NULL, NULL);
	g_flow = CreateWindowExW(0, WC_LISTVIEWW, NULL,
	                         WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
	                         360, 78, w - 372, 400, parent, (HMENU)ID_FLOW_LV, NULL, NULL);
	add_col(g_flow, 0, L"IP source", 140);
	add_col(g_flow, 1, L"Port", 56);
	add_col(g_flow, 2, L"→", 28);
	add_col(g_flow, 3, L"IP destination", 140);
	add_col(g_flow, 4, L"Port", 56);
	add_col(g_flow, 5, L"Proto", 52);
	add_col(g_flow, 6, L"Trafic", 72);
	add_col(g_flow, 7, L"#", 44);
	add_col(g_flow, 8, L"Détail", 280);

	g_hdr_pkt = CreateWindowExW(0, L"STATIC", L"  Paquets en direct", WS_CHILD | WS_VISIBLE, 360, 460,
	                            400, 20, parent, NULL, NULL, NULL);
	g_pkt = CreateWindowExW(0, WC_LISTVIEWW, NULL,
	                        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
	                        360, 482, w - 372, 160, parent, (HMENU)ID_PKT_LV, NULL, NULL);
	add_col(g_pkt, 0, L"Source", 180);
	add_col(g_pkt, 1, L"Destination", 180);
	add_col(g_pkt, 2, L"Proto", 56);
	add_col(g_pkt, 3, L"Info", 360);
	add_col(g_pkt, 4, L"o", 48);

	g_hex = CreateWindowExW(0, L"EDIT", NULL,
	                        WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY,
	                        0, 0, 0, 0, parent, (HMENU)ID_HEX, NULL, NULL);

	g_status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 0, 0, w,
	                           STATUS_H, parent, NULL, NULL, NULL);

	g_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
	                     OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
	                     DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	g_font_bold = CreateFontW(-14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
	                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
	                          DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	g_font_sec = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
	                         OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
	                         DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	HWND ctrls[] = {g_adapter, g_app_tree, g_filter, g_hosts, g_flow, g_pkt, g_hex, g_status,
	                g_lbl_if, g_lbl_filt};
	for (size_t ci = 0; ci < sizeof(ctrls) / sizeof(ctrls[0]); ci++)
		SendMessageW(ctrls[ci], WM_SETFONT, (WPARAM)g_font, TRUE);
	g_toolbar_oldproc = (WNDPROC)SetWindowLongPtrW(g_toolbar_bg, GWLP_WNDPROC, (LONG_PTR)toolbar_bg_proc);
	SendMessageW(g_app_tree, WM_SETFONT, (WPARAM)g_font, TRUE);
	SetWindowTheme(g_filter, L"DarkMode_CFD", L"Explorer");
	SetWindowTheme(g_app_tree, L"DarkMode_Explorer", NULL);
	SendMessageW(g_app_tree, TVM_SETBKCOLOR, 0, (LPARAM)CLR_ROW);
	SendMessageW(g_app_tree, TVM_SETTEXTCOLOR, 0, (LPARAM)CLR_TEXT);
	sniffer_proc_refresh();
	fill_app_tree();
	style_dark_listview(g_hosts);
	style_dark_listview(g_flow);
	style_dark_listview(g_pkt);
	lv_hook_scroll(g_hosts, LV_SLOT_HOSTS);
	lv_hook_scroll(g_flow, LV_SLOT_FLOW);
	lv_hook_scroll(g_pkt, LV_SLOT_PKT);
	SetWindowPos(g_toolbar_bg, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	relayout();
}

static void update_status(void) {
	if (!g_sizing && (g_tick % STATUS_TICKS) != 0)
		return;
	sniffer_stats_t st;
	sniffer_stats(&st);
	int fc = sniffer_insight_flow_count();
	int hc = sniffer_insight_host_count();
	const wchar_t *cap = st.capturing ? L"● CAPTURE" : L"○ pause";
	if ((uint64_t)st.packets_captured == g_status_pkts && st.bytes_captured == g_status_bytes &&
	    fc == g_status_flows && hc == g_status_hosts && wcscmp(cap, g_status_cap) == 0)
		return;
	g_status_pkts = (int)st.packets_captured;
	g_status_bytes = st.bytes_captured;
	g_status_flows = fc;
	g_status_hosts = hc;
	wcscpy(g_status_cap, cap);
	wchar_t msg[512];
	swprintf(msg, 512, L"  Paquets %llu  |  %llu octets  |  Connexions %d  |  IP actives %d  |  %s",
	         (unsigned long long)st.packets_captured, (unsigned long long)st.bytes_captured, fc, hc,
	         cap);
	SetWindowTextW(g_status, msg);
}

static COLORREF lv_text_color(HWND lv, int item) {
	(void)lv;
	if (item < 0)
		return CLR_TEXT;
	return CLR_IP;
}

static LRESULT on_lv_customdraw(LPNMLVCUSTOMDRAW cd) {
	COLORREF bk = (cd->nmcd.dwItemSpec % 2) ? CLR_ROW : CLR_ROW_ALT;
	COLORREF fg = lv_text_color(cd->nmcd.hdr.hwndFrom, (int)cd->nmcd.dwItemSpec);
	if (cd->nmcd.uItemState & CDIS_SELECTED)
		bk = CLR_SEL;
	if (cd->nmcd.uItemState & CDIS_SELECTED)
		fg = CLR_SEL_TXT;
	switch (cd->nmcd.dwDrawStage) {
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW;
	case CDDS_ITEMPREPAINT:
		cd->clrTextBk = bk;
		cd->clrText = fg;
		return CDRF_NOTIFYSUBITEMDRAW;
	case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
		cd->clrTextBk = bk;
		cd->clrText = fg;
		return CDRF_DODEFAULT;
	}
	return CDRF_DODEFAULT;
}

static LRESULT on_tv_customdraw(LPNMTVCUSTOMDRAW cd) {
	switch (cd->nmcd.dwDrawStage) {
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW;
	case CDDS_ITEMPREPAINT:
		if (cd->nmcd.uItemState & CDIS_SELECTED)
			cd->clrTextBk = CLR_SEL;
		else
			cd->clrTextBk = CLR_ROW;
		cd->clrText = CLR_TEXT;
		return CDRF_DODEFAULT;
	}
	return CDRF_DODEFAULT;
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
	switch (msg) {
	case WM_CREATE:
		g_hwnd = hwnd;
		g_hinst = ((LPCREATESTRUCT)lp)->hInstance;
		g_filter_txt[0] = 0;
		g_tick = 0;
		g_ui_tick = 0;
		g_sizing = 0;
		g_status_bytes = (uint64_t)-1;
		g_br_bg = CreateSolidBrush(CLR_BG);
		g_br_card = CreateSolidBrush(CLR_CARD);
		g_br_edit = CreateSolidBrush(CLR_ROW);
		g_br_tool = CreateSolidBrush(CLR_TOOLBAR);
		g_br_header = CreateSolidBrush(CLR_HEADER);
			apply_window_chrome(hwnd);
		if (g_app_icon) {
			SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)g_app_icon);
			SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)g_app_icon);
		}
		sniffer_proc_init();
		create_ui(hwnd);
		if (sniffer_init() == 0) {
			init_adapter_index();
			on_start();
		}
		update_status();
		SetTimer(hwnd, ID_TIMER, 50, NULL);
		SetTimer(hwnd, ID_TIMER_UI, 100, NULL);
		tray_show(hwnd);
		return 0;
	case WM_CLOSE:
		ShowWindow(hwnd, SW_HIDE);
		return 0;
	case WM_TRAY:
		if (lp == WM_LBUTTONDBLCLK) {
			ShowWindow(hwnd, SW_RESTORE);
			SetForegroundWindow(hwnd);
		} else if (lp == WM_RBUTTONUP) {
			POINT pt;
			GetCursorPos(&pt);
			HMENU menu = CreatePopupMenu();
			AppendMenuW(menu, MF_STRING, ID_TRAY_SHOW, L"Afficher Sniffer");
			AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
			AppendMenuW(menu, MF_STRING, ID_TRAY_QUIT, L"Quitter");
			SetForegroundWindow(hwnd);
			TrackPopupMenu(menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, NULL);
			DestroyMenu(menu);
		}
		return 0;
	case WM_ENTERSIZEMOVE:
		g_sizing = 1;
		lv_freeze(g_hosts, TRUE);
		lv_freeze(g_flow, TRUE);
		lv_freeze(g_pkt, TRUE);
		return 0;
	case WM_EXITSIZEMOVE:
		g_sizing = 0;
		lv_freeze(g_hosts, FALSE);
		lv_freeze(g_flow, FALSE);
		lv_freeze(g_pkt, FALSE);
		relayout();
		ui_raise();
		InvalidateRect(hwnd, NULL, FALSE);
		return 0;
	case WM_SIZE:
		relayout();
		return 0;
	case WM_ERASEBKGND:
		SelectObject((HDC)wp, g_br_bg);
		RECT er;
		GetClientRect(hwnd, &er);
		ExtTextOutW((HDC)wp, 0, 0, ETO_OPAQUE, &er, NULL, 0, NULL);
		return 1;
	case WM_PAINT:
		paint_chrome(hwnd);
		return 0;
	case WM_GETMINMAXINFO: {
		MINMAXINFO *mm = (MINMAXINFO *)lp;
		mm->ptMinTrackSize.x = 900;
		mm->ptMinTrackSize.y = 560;
		return 0;
	}
	case WM_TIMER:
		if (wp == ID_TIMER) {
			poll_packets();
			update_status();
		} else if (wp == ID_TIMER_UI) {
			on_ui_timer();
		}
		return 0;
	case WM_COMMAND:
		switch (LOWORD(wp)) {
		case ID_FILTER:
			if (HIWORD(wp) == EN_CHANGE) {
				GetWindowTextW(g_filter, g_filter_txt, 160);
				refresh_insight_lists();
			}
			break;
		case ID_TRAY_SHOW:
			ShowWindow(hwnd, SW_RESTORE);
			SetForegroundWindow(hwnd);
			break;
		case ID_TRAY_QUIT:
			tray_quit(hwnd);
			break;
		default:
			if (LOWORD(wp) >= ID_IFACE_BASE && LOWORD(wp) < ID_IFACE_BASE + 48) {
				g_adapter_idx = LOWORD(wp) - ID_IFACE_BASE;
				on_start();
			}
			break;
		}
		return 0;
	case WM_NOTIFY: {
		LPNMHDR nh = (LPNMHDR)lp;
		if (nh->idFrom == ID_APP_TREE && nh->code == NM_CUSTOMDRAW)
			return on_tv_customdraw((LPNMTVCUSTOMDRAW)lp);
		if (nh->idFrom == ID_APP_TREE && nh->code == TVN_SELCHANGED && !g_tree_busy) {
			TVITEM it = {0};
			HTREEITEM sel = TreeView_GetSelection(g_app_tree);
			if (sel) {
				it.mask = TVIF_PARAM;
				it.hItem = sel;
				TreeView_GetItem(g_app_tree, &it);
				on_app_tree_select(it.lParam);
			}
		}
		if (nh->code == NM_CUSTOMDRAW && is_list_hdr(nh->hwndFrom))
			return on_hdr_customdraw((LPNMCUSTOMDRAW)lp);
		if ((nh->idFrom == ID_FLOW_LV || nh->idFrom == ID_HOST_LV || nh->idFrom == ID_PKT_LV) &&
		    nh->code == NM_CUSTOMDRAW)
			return on_lv_customdraw((LPNMLVCUSTOMDRAW)lp);
		if (nh->idFrom == ID_PKT_LV && nh->code == LVN_ITEMCHANGED) {
			LPNMLISTVIEW lv = (LPNMLISTVIEW)lp;
			if ((lv->uChanged & LVIF_STATE) && (lv->uNewState & LVIS_SELECTED)) {
				LVITEMW it = {0};
				it.mask = LVIF_PARAM;
				it.iItem = lv->iItem;
				if (ListView_GetItem(g_pkt, &it)) {
					const sniffer_packet_t *p = &g_cache[it.lParam % GUI_PKT_CACHE];
					wchar_t buf[4096];
					size_t pos = 0;
					for (unsigned off = 0; off < p->caplen && off < 256 && pos < 3800; off += 16) {
						wchar_t ln[128];
						swprintf(ln, 128, L"%04x  ", off);
						wcscpy(buf + pos, ln);
						pos += wcslen(ln);
						for (unsigned i = 0; i < 16 && off + i < p->caplen; i++) {
							swprintf(ln, 128, L"%02x ", p->payload[off + i]);
							wcscpy(buf + pos, ln);
							pos += wcslen(ln);
						}
						buf[pos++] = L'\n';
						buf[pos] = 0;
					}
					SetWindowTextW(g_hex, buf);
					update_status();
				}
			}
		}
		break;
	}
	case WM_CTLCOLORLISTBOX: {
		SetTextColor((HDC)wp, CLR_TEXT);
		SetBkColor((HDC)wp, CLR_ROW);
		return (LRESULT)g_br_edit;
	}
	case WM_CTLCOLORSTATIC: {
		HWND who = (HWND)lp;
		HDC hdc = (HDC)wp;
		if (who == g_adapter) {
			SetBkColor(hdc, CLR_CARD);
			SetTextColor(hdc, CLR_TEXT);
			return (LRESULT)g_br_card;
		}
		if (who == g_toolbar_bg) {
			SetBkColor(hdc, CLR_BG);
			SetTextColor(hdc, CLR_MUTED);
			return (LRESULT)g_br_bg;
		}
		if (who == g_status) {
			SetTextColor(hdc, CLR_MUTED);
			SetBkColor(hdc, CLR_BG);
			return (LRESULT)g_br_bg;
		}
		SetTextColor(hdc, CLR_MUTED);
		SetBkColor(hdc, CLR_BG);
		return (LRESULT)g_br_bg;
	}
	case WM_CTLCOLORBTN:
		return (LRESULT)g_br_tool;
	case WM_CTLCOLOREDIT: {
		HWND who = (HWND)lp;
		HDC hdc = (HDC)wp;
		SetTextColor(hdc, CLR_TEXT);
		SetBkColor(hdc, CLR_CARD);
		if (who == g_filter)
			SetBkColor(hdc, CLR_ROW);
		return (LRESULT)(who == g_filter ? g_br_edit : g_br_card);
	}
	case WM_DESTROY:
		tray_hide();
		KillTimer(hwnd, ID_TIMER);
		KillTimer(hwnd, ID_TIMER_UI);
		sniffer_stop();
		sniffer_proc_shutdown();
		sniffer_shutdown();
		DeleteObject(g_font);
		DeleteObject(g_font_bold);
		DeleteObject(g_br_bg);
		DeleteObject(g_br_card);
		DeleteObject(g_br_edit);
		DeleteObject(g_br_tool);
		DeleteObject(g_br_header);
		DeleteObject(g_font_sec);
		logo_unload();
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show) {
	(void)prev;
	(void)cmd;
	g_hinst = inst;
	if (!logo_load(inst))
		g_app_icon = LoadIconW(NULL, IDI_APPLICATION);
	INITCOMMONCONTROLSEX icc = {.dwSize = sizeof(icc),
	                            .dwICC = ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES |
	                                     ICC_STANDARD_CLASSES};
	InitCommonControlsEx(&icc);
	WNDCLASSW wc = {0};
	wc.lpfnWndProc = wndproc;
	wc.hInstance = inst;
	wc.lpszClassName = L"SnifferNetView";
	wc.hbrBackground = CreateSolidBrush(CLR_BG);
	wc.hIcon = g_app_icon;
	RegisterClassW(&wc);
	HWND win = CreateWindowExW(0, wc.lpszClassName, L"Sniffer — Connexions & IP",
	                           WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_MINIMIZEBOX | WS_MAXIMIZEBOX |
	                               WS_SYSMENU | WS_CAPTION | WS_CLIPCHILDREN,
	                           CW_USEDEFAULT, CW_USEDEFAULT, 1480, 920, NULL, NULL, inst, NULL);
	apply_window_chrome(win);
	ShowWindow(win, show);
	MSG msg;
	while (GetMessageW(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
	return (int)msg.wParam;
}
