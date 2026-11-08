module main

import gg
import strings
#flag windows -DSNIFFER_STATIC
#flag windows -I../core
#flag windows -L../build
#flag windows -lsniffer_core -lws2_32

#include "sniffer_core.h"

const win_w          = 1280
const win_h          = 800
const max_visible    = 22
const max_stored     = 600
const hex_lines      = 14

const col_bg         = gg.Color{11, 15, 25, 255}
const col_panel      = gg.Color{22, 30, 46, 255}
const col_panel2     = gg.Color{30, 41, 59, 255}
const col_border     = gg.Color{51, 65, 85, 255}
const col_text       = gg.Color{226, 232, 240, 255}
const col_muted      = gg.Color{148, 163, 184, 255}
const col_accent     = gg.Color{56, 189, 248, 255}
const col_btn        = gg.Color{14, 165, 233, 255}
const col_btn_hover  = gg.Color{2, 132, 199, 255}
const col_btn_stop   = gg.Color{239, 68, 68, 255}
const col_row_alt    = gg.Color{15, 23, 42, 180}
const col_row_sel    = gg.Color{30, 58, 138, 200}
const col_tcp        = gg.Color{74, 222, 128, 255}
const col_udp        = gg.Color{251, 191, 36, 255}
const col_icmp       = gg.Color{244, 114, 182, 255}
const col_arp        = gg.Color{167, 139, 250, 255}

struct PacketRow {
	ts      u64
	proto   string
	src     string
	dst     string
	info    string
	caplen  u32
	raw     []u8
}

@[heap]
struct App {
mut:
	packets      []PacketRow
	devices      []string
	dev_desc     []string
	sel_dev      int
	sel_packet   int
	scroll       int
	capturing    bool
	init_ok      bool
	err_msg      string
	stats_pkts   u64
	stats_bytes  u64
	stats_drop   u64
	btn_start    gg.Rect
	btn_stop     gg.Rect
	hover_start  bool
	hover_stop   bool
	last_poll    i64
}

fn C.sniffer_init() int
fn C.sniffer_shutdown()
fn C.sniffer_device_count() int
fn C.sniffer_device_get(index int, name &u8, name_len usize, desc &u8, desc_len usize) int
fn C.sniffer_start(device &u8, bpf &u8) int
fn C.sniffer_stop() int
fn C.sniffer_poll(out &C.sniffer_packet_t) int
fn C.sniffer_stats(out &C.sniffer_stats_t)
fn C.sniffer_proto_name(p C.sniffer_proto_t) &u8

fn proto_color(name string) gg.Color {
	lname := name.to_lower()
	if lname == 'tcp' {
		return col_tcp
	}
	if lname == 'udp' {
		return col_udp
	}
	if lname == 'icmp' {
		return col_icmp
	}
	if lname == 'arp' {
		return col_arp
	}
	return col_accent
}

fn (mut app App) refresh_devices() {
	n := C.sniffer_device_count()
	app.devices = []string{len: n}
	app.dev_desc = []string{len: n}
	for i in 0 .. n {
		mut name := []u8{len: 256}
		mut desc := []u8{len: 512}
		C.sniffer_device_get(i, name.data, name.len, desc.data, desc.len)
		app.devices[i] = unsafe { name.bytestr() }
		app.dev_desc[i] = unsafe { desc.bytestr() }
	}
	if app.sel_dev >= n {
		app.sel_dev = 0
	}
}

fn (mut app App) pull_packets() {
	for _ in 0 .. 64 {
		mut pkt := C.sniffer_packet_t{}
		if C.sniffer_poll(&pkt) == 0 {
			break
		}
		l3 := unsafe { C.sniffer_proto_name(pkt.l3).vstring() }
		l4 := unsafe { C.sniffer_proto_name(pkt.l4).vstring() }
		proto := if pkt.l4 != .other { l4 } else { l3 }
		mut raw := []u8{len: int(pkt.caplen)}
		if pkt.caplen > 0 {
			unsafe {
				vmemcpy(raw.data, pkt.payload.data, pkt.caplen)
			}
		}
		app.packets << PacketRow{
			ts: pkt.timestamp_ms
			proto: proto
			src: pkt.src.vstring()
			dst: pkt.dst.vstring()
			info: pkt.info.vstring()
			caplen: pkt.caplen
			raw: raw
		}
	}
	for app.packets.len > max_stored {
		app.packets.delete(0)
		if app.sel_packet > 0 {
			app.sel_packet--
		}
	}
}

fn (mut app App) refresh_stats() {
	mut st := C.sniffer_stats_t{}
	C.sniffer_stats(&st)
	app.stats_pkts = st.packets_captured
	app.stats_bytes = st.bytes_captured
	app.stats_drop = st.dropped
	app.capturing = st.capturing != 0
	if st.last_error[0] != 0 {
		app.err_msg = st.last_error.vstring()
	}
}

fn (mut app App) toggle_capture(start bool) {
	if start {
		if app.sel_dev < 0 || app.sel_dev >= app.devices.len {
			return
		}
		dev := app.devices[app.sel_dev]
		C.sniffer_stop()
		rc := C.sniffer_start(dev.str, 0)
		if rc != 0 {
			app.refresh_stats()
		} else {
			app.err_msg = ''
		}
	} else {
		C.sniffer_stop()
		app.capturing = false
	}
}

fn point_in(r gg.Rect, x f32, y f32) bool {
	return x >= r.x && x <= r.x + r.w && y >= r.y && y <= r.y + r.h
}

fn draw_panel(ctx &gg.Context, x f32, y f32, w f32, h f32) {
	ctx.draw_rect_filled(x, y, w, h, col_panel)
	ctx.draw_rect(x, y, w, h, col_border)
}

fn draw_button(ctx &gg.Context, r gg.Rect, label string, base gg.Color, hover bool) {
	c := if hover { gg.Color{base.r + 25, base.g + 25, base.b + 25, base.a} } else { base }
	ctx.draw_rect_filled(r.x, r.y, r.w, r.h, c)
	ctx.draw_rect(r.x, r.y, r.w, r.h, col_border)
	ctx.draw_text(r.x + 14, r.y + 10, label, color: col_text, size: 16)
}

fn format_bytes(n u64) string {
	if n < 1024 {
		return '${n} o'
	}
	if n < 1024 * 1024 {
		return '${n / 1024} Ko'
	}
	return '${n / (1024 * 1024)} Mo'
}

fn hex_line(data []u8, off int) string {
	mut line := strings.Builder{}
	line.write('${off:04x}  ')
	end := off + 16
	if end > data.len {
		end = data.len
	}
	for i in off .. end {
		line.write('${data[i]:02x} ')
		if i == off + 7 {
			line.write(' ')
		}
	}
	for i in end .. off + 16 {
		line.write('   ')
		if i == off + 7 {
			line.write(' ')
		}
	}
	line.write(' |')
	for i in off .. end {
		c := data[i]
		ch := if c >= 32 && c <= 126 { c.ascii_str() } else { '.' }
		line.write(ch)
	}
	line.write('|')
	return line.str()
}

fn frame(ctx &gg.Context) {
	mut app := unsafe { &App(ctx.user_data) }

	app.pull_packets()
	now := time.ticks()
	if now - app.last_poll > 200 {
		app.refresh_stats()
		app.last_poll = now
	}

	ctx.begin()
	ctx.draw_rect_filled(0, 0, f32(ctx.width), f32(ctx.height), col_bg)

	draw_panel(ctx, 16, 12, f32(ctx.width) - 32, 64)
	ctx.draw_text(32, 28, 'Sniffer — Noyau C + asm x86 · GUI V', color: col_text, size: 22)
	stats := 'Paquets: ${app.stats_pkts}   Volume: ${format_bytes(app.stats_bytes)}   Perdus: ${app.stats_drop}'
	ctx.draw_text(420, 34, stats, color: col_muted, size: 15)
	status := if app.capturing { '● CAPTURE' } else { '○ ARRÊT' }
	status_col := if app.capturing { col_tcp } else { col_muted }
	ctx.draw_text(f32(ctx.width) - 180, 34, status, color: status_col, size: 16)

	app.btn_start = gg.Rect{f32(ctx.width) - 250, 24, 100, 32}
	app.btn_stop = gg.Rect{f32(ctx.width) - 140, 24, 100, 32}
	draw_button(ctx, app.btn_start, 'Démarrer', col_btn, app.hover_start)
	draw_button(ctx, app.btn_stop, 'Stop', col_btn_stop, app.hover_stop)

	if app.err_msg.len > 0 {
		ctx.draw_text(32, 52, app.err_msg, color: col_btn_stop, size: 13)
	}

	draw_panel(ctx, 16, 88, 280, f32(ctx.height) - 104)
	ctx.draw_text(28, 100, 'Interfaces Npcap', color: col_accent, size: 17)
	mut dy := f32(130)
	for i, name in app.devices {
		row := gg.Rect{24, dy - 4, 264, 46}
		is_sel := i == app.sel_dev
		if is_sel {
			ctx.draw_rect_filled(row.x, row.y, row.w, row.h, col_row_sel)
		} else if i % 2 == 0 {
			ctx.draw_rect_filled(row.x, row.y, row.w, row.h, col_row_alt)
		}
		ctx.draw_text(32, dy, name, color: col_text, size: 14)
		desc := if i < app.dev_desc.len { app.dev_desc[i] } else { '' }
		if desc.len > 42 {
			ctx.draw_text(32, dy + 18, desc[..42] + '…', color: col_muted, size: 12)
		} else {
			ctx.draw_text(32, dy + 18, desc, color: col_muted, size: 12)
		}
		dy += 52
	}

	table_x := f32(308)
	table_y := f32(88)
	table_w := f32(ctx.width) - 324
	table_h := f32(380)
	draw_panel(ctx, table_x, table_y, table_w, table_h)
	ctx.draw_text(table_x + 12, table_y + 10, 'Flux en direct', color: col_accent, size: 17)

	header_y := table_y + 38
	ctx.draw_text(table_x + 12, header_y, 'Heure', color: col_muted, size: 13)
	ctx.draw_text(table_x + 90, header_y, 'Proto', color: col_muted, size: 13)
	ctx.draw_text(table_x + 150, header_y, 'Source', color: col_muted, size: 13)
	ctx.draw_text(table_x + 340, header_y, 'Destination', color: col_muted, size: 13)
	ctx.draw_text(table_x + 530, header_y, 'Info', color: col_muted, size: 13)

	vis_start := app.scroll
	if app.sel_packet < vis_start {
		vis_start = app.sel_packet
	}
	if app.sel_packet >= vis_start + max_visible {
		vis_start = app.sel_packet - max_visible + 1
	}
	app.scroll = vis_start

	mut row_y := header_y + 22
	for i in vis_start .. app.packets.len {
		if i - vis_start >= max_visible {
			break
		}
		p := app.packets[i]
		if i == app.sel_packet {
			ctx.draw_rect_filled(table_x + 8, row_y - 2, table_w - 16, 22, col_row_sel)
		} else if i % 2 == 0 {
			ctx.draw_rect_filled(table_x + 8, row_y - 2, table_w - 16, 22, col_row_alt)
		}
		ctx.draw_text(table_x + 12, row_y, '${p.ts % 100000}', color: col_muted, size: 13)
		ctx.draw_text(table_x + 90, row_y, p.proto, color: proto_color(p.proto), size: 13)
		ctx.draw_text(table_x + 150, row_y, p.src, color: col_text, size: 13)
		ctx.draw_text(table_x + 340, row_y, p.dst, color: col_text, size: 13)
		ctx.draw_text(table_x + 530, row_y, p.info, color: col_muted, size: 13)
		row_y += 22
	}

	hex_y := table_y + table_h + 12
	hex_h := f32(ctx.height) - hex_y - 16
	draw_panel(ctx, table_x, hex_y, table_w, hex_h)
	ctx.draw_text(table_x + 12, hex_y + 10, 'Dump hexadécimal', color: col_accent, size: 17)
	if app.sel_packet >= 0 && app.sel_packet < app.packets.len {
		raw := app.packets[app.sel_packet].raw
		mut hy := hex_y + 36
		for line := 0; line < hex_lines; line++ {
			off := line * 16
			if off >= raw.len {
				break
			}
			ctx.draw_text(table_x + 16, hy, hex_line(raw, off), color: col_text, size: 14)
			hy += 18
		}
	} else {
		ctx.draw_text(table_x + 16, hex_y + 40, 'Sélectionnez un paquet dans la liste.', color: col_muted,
			size: 14)
	}

	ctx.end()
}

fn click(x f32, y f32, button gg.MouseButton, data voidptr) {
	if button != .left {
		return
	}
	mut app := unsafe { &App(data) }
	if point_in(app.btn_start, x, y) {
		app.toggle_capture(true)
		return
	}
	if point_in(app.btn_stop, x, y) {
		app.toggle_capture(false)
		return
	}
	if x >= 24 && x <= 288 && y >= 126 {
		idx := int((y - 126) / 52)
		if idx >= 0 && idx < app.devices.len {
			app.sel_dev = idx
		}
	}
	table_x := f32(308)
	table_y := f32(88)
	if x >= table_x && x <= win_w - 16 && y >= table_y + 60 && y <= table_y + 380 {
		row := int((y - (table_y + 60)) / 22)
		pi := app.scroll + row
		if pi >= 0 && pi < app.packets.len {
			app.sel_packet = pi
		}
	}
}

fn move(x f32, y f32, data voidptr) {
	mut app := unsafe { &App(data) }
	app.hover_start = point_in(app.btn_start, x, y)
	app.hover_stop = point_in(app.btn_stop, x, y)
}

fn scroll_event(e &gg.Event, data voidptr) {
	if e.scroll_y == 0 {
		return
	}
	mut app := unsafe { &App(data) }
	if e.mouse_x >= 308 && e.mouse_y >= 88 && e.mouse_y <= 468 {
		if e.scroll_y > 0 && app.scroll > 0 {
			app.scroll--
		}
		if e.scroll_y < 0 && app.scroll + max_visible < app.packets.len {
			app.scroll++
		}
	}
}

fn main() {
	mut app := &App{}
	rc := C.sniffer_init()
	app.init_ok = rc == 0
	if !app.init_ok {
		mut st := C.sniffer_stats_t{}
		C.sniffer_stats(&st)
		app.err_msg = st.last_error.vstring()
	} else {
		app.refresh_devices()
	}

	gg.start(gg.Config{
		width:        win_w
		height:       win_h
		window_title: 'Sniffer — C · asm x86 · V'
		bg_color:     col_bg
		user_data:    app
		frame_fn:     frame
		click_fn:     click
		move_fn:      move
		scroll_fn:    scroll_event
		font_size:    16
	})

	C.sniffer_stop()
	C.sniffer_shutdown()
}
