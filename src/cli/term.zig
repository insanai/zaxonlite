//! The libvaxis seam (ZDS 0005, M2).
//!
//! This is the only CLI module that imports libvaxis directly. It owns TTY
//! probing, raw-mode enter/leave, decoded key events, display-width math,
//! and the ANSI style constants. Every other `cli/` module sees the library
//! through this file's re-exports, which bounds the blast radius if the
//! dependency ever has to be replaced.

const std = @import("std");
const builtin = @import("builtin");
const vaxis = @import("vaxis");

pub const Key = vaxis.Key;
pub const Event = vaxis.Event;
pub const GraphemeIterator = vaxis.unicode.GraphemeIterator;

/// Panic namespace for the executable root: restores the terminal (when
/// the rich shell holds it) before the default panic handler runs. Not
/// `vaxis.Panic` because upstream still carries the pre-0.16 `call`
/// signature; the recovery path is the library's own.
pub const Panic = std.debug.FullPanic(panicCall);

fn panicCall(msg: []const u8, ret_addr: ?usize) noreturn {
    vaxis.recover();
    std.debug.defaultPanic(msg, ret_addr);
}

const is_windows = builtin.os.tag == .windows;

/// Returns the display-cell width of a byte string, counting grapheme
/// clusters and East Asian width, so `wo/rld` and emoji math is correct.
pub fn displayWidth(bytes: []const u8) u16 {
    return vaxis.gwidth.gwidth(bytes, .unicode);
}

/// What the terminal supports; decided once at startup from the
/// environment rather than by capability queries, because the shell is an
/// inline REPL that never takes over the screen.
pub const Caps = struct {
    color: bool,
    unicode: bool,
};

/// Whether the rich interactive path is available at all, and with which
/// capabilities. The rich path requires stdin and stdout to both be TTYs
/// and TERM to name a capable terminal; anything else keeps the plain
/// line-reader loop so pipes and scripts observe no change.
pub const Detection = struct {
    interactive: bool,
    caps: Caps,
};

pub fn detect(
    io: std.Io,
    environ: *std.process.Environ.Map,
    no_color_flag: bool,
) Detection {
    const stdin_tty = std.Io.File.stdin().isTty(io) catch false;
    const stdout_tty = std.Io.File.stdout().isTty(io) catch false;
    const term_name = environ.get("TERM") orelse "";
    const dumb = std.mem.eql(u8, term_name, "dumb");
    const interactive = stdin_tty and stdout_tty and
        (is_windows or (term_name.len > 0 and !dumb));
    const color = interactive and !no_color_flag and
        environ.get("NO_COLOR") == null;
    const unicode = blk: {
        if (!interactive) break :blk false;
        if (is_windows) break :blk true;
        const lang = environ.get("LC_ALL") orelse
            environ.get("LC_CTYPE") orelse
            environ.get("LANG") orelse "";
        break :blk std.ascii.indexOfIgnoreCase(lang, "utf-8") != null or
            std.ascii.indexOfIgnoreCase(lang, "utf8") != null;
    };
    return .{
        .interactive = interactive,
        .caps = .{ .color = color, .unicode = unicode },
    };
}

/// SGR fragments used by the rich renderer and repaint. Styling always goes
/// through `Style` so a non-color terminal renders the same bytes minus the
/// escapes.
pub const Style = struct {
    color: bool,

    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const italic = "\x1b[3m";
    pub const fg_keyword = "\x1b[36m"; // cyan
    pub const fg_string = "\x1b[32m"; // green
    pub const fg_number = "\x1b[33m"; // yellow
    pub const fg_comment = "\x1b[90m"; // bright black
    pub const fg_dot = "\x1b[35m"; // magenta

    pub fn write(self: Style, out: *std.Io.Writer, sequence: []const u8) !void {
        if (self.color) try out.writeAll(sequence);
    }
};

/// The interactive terminal: raw-mode lifecycle plus decoded events.
///
/// Ordering contract: `init` enters raw mode immediately; callers MUST
/// leave raw mode (`suspendRaw`) before printing multi-line results through
/// ordinary writers, because raw mode disables output post-processing.
/// `deinit` restores the terminal on every path and is idempotent.
pub const Term = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    tty: vaxis.Tty,
    parser: vaxis.Parser = .{},
    caps: Caps,
    raw: bool,
    write_buffer: []u8,
    pending: [512]u8 = undefined,
    pending_start: usize = 0,
    pending_len: usize = 0,

    pub const Error = error{ TtyUnavailable, OutOfMemory };

    pub fn init(gpa: std.mem.Allocator, io: std.Io, caps: Caps) Error!Term {
        const write_buffer = try gpa.alloc(u8, 4096);
        errdefer gpa.free(write_buffer);
        const tty = vaxis.Tty.init(io, write_buffer) catch
            return error.TtyUnavailable;
        return .{
            .io = io,
            .gpa = gpa,
            .tty = tty,
            .caps = caps,
            .raw = true,
            .write_buffer = write_buffer,
        };
    }

    pub fn deinit(self: *Term) void {
        self.writer().flush() catch {};
        // Tty.deinit restores the saved terminal state; a prior suspendRaw
        // makes that restore a no-op rather than an error.
        self.tty.deinit();
        vaxis.tty.Tty.resetSignalHandler();
        self.gpa.free(self.write_buffer);
        self.raw = false;
    }

    /// Leaves raw mode so results and diagnostics can be printed through
    /// the ordinary cooked-mode writers. Idempotent. `.DRAIN`, never
    /// `.FLUSH`: flushing would silently discard type-ahead keys pressed
    /// while a statement was executing.
    pub fn suspendRaw(self: *Term) void {
        if (!self.raw) return;
        self.writer().flush() catch {};
        if (is_windows) {
            const W = vaxis.tty.WindowsTty;
            W.setConsoleMode(self.tty.stdin, self.tty.initial_input_mode) catch {};
            W.setConsoleMode(self.tty.stdout, self.tty.initial_output_mode) catch {};
        } else {
            std.posix.tcsetattr(self.tty.fd.handle, .DRAIN, self.tty.termios) catch {};
        }
        self.raw = false;
    }

    /// Re-enters raw mode for the next edited line. Idempotent. Applies
    /// the same flag set as the library's raw entry but with `.DRAIN`, so
    /// pending input survives the transition.
    pub fn resumeRaw(self: *Term) void {
        if (self.raw) return;
        if (is_windows) {
            const W = vaxis.tty.WindowsTty;
            W.setConsoleMode(self.tty.stdin, W.input_raw_mode) catch {};
            W.setConsoleMode(self.tty.stdout, W.output_raw_mode) catch {};
        } else {
            var raw_state = self.tty.termios;
            raw_state.iflag.IGNBRK = false;
            raw_state.iflag.BRKINT = false;
            raw_state.iflag.PARMRK = false;
            raw_state.iflag.ISTRIP = false;
            raw_state.iflag.INLCR = false;
            raw_state.iflag.IGNCR = false;
            raw_state.iflag.ICRNL = false;
            raw_state.iflag.IXON = false;
            raw_state.oflag.OPOST = false;
            raw_state.lflag.ECHO = false;
            raw_state.lflag.ECHONL = false;
            raw_state.lflag.ICANON = false;
            raw_state.lflag.ISIG = false;
            raw_state.lflag.IEXTEN = false;
            raw_state.cflag.CSIZE = .CS8;
            raw_state.cflag.PARENB = false;
            raw_state.cc[@intFromEnum(std.posix.V.MIN)] = 1;
            raw_state.cc[@intFromEnum(std.posix.V.TIME)] = 0;
            std.posix.tcsetattr(self.tty.fd.handle, .DRAIN, raw_state) catch {};
        }
        self.raw = true;
    }

    /// Buffered writer to the terminal itself. In raw mode, line breaks
    /// must be written as "\r\n".
    pub fn writer(self: *Term) *std.Io.Writer {
        return self.tty.writer();
    }

    /// The terminal width in cells, with a safe floor so width math never
    /// divides by zero on degenerate reports.
    pub fn width(self: *Term) u16 {
        if (is_windows) return 80;
        const winsize = self.tty.getWinsize() catch return 80;
        return if (winsize.cols < 8) 80 else @intCast(winsize.cols);
    }

    pub fn height(self: *Term) u16 {
        if (is_windows) return 24;
        const winsize = self.tty.getWinsize() catch return 24;
        return if (winsize.rows < 2) 24 else @intCast(winsize.rows);
    }

    /// Blocks until the next decoded terminal event.
    pub fn nextEvent(self: *Term) !Event {
        if (is_windows) {
            return self.tty.nextEvent(&self.parser, null);
        }
        while (true) {
            if (self.pending_len > self.pending_start) {
                const slice = self.pending[self.pending_start..self.pending_len];
                const result = self.parser.parse(slice, null) catch {
                    // Undecodable bytes are dropped, never echoed.
                    self.pending_start = self.pending_len;
                    continue;
                };
                if (result.n > 0) {
                    self.pending_start += result.n;
                    if (self.pending_start >= self.pending_len) {
                        self.pending_start = 0;
                        self.pending_len = 0;
                    }
                    if (result.event) |event| return event;
                    continue;
                }
            }
            // Need more bytes: compact, then read.
            if (self.pending_start > 0) {
                std.mem.copyForwards(
                    u8,
                    &self.pending,
                    self.pending[self.pending_start..self.pending_len],
                );
                self.pending_len -= self.pending_start;
                self.pending_start = 0;
            }
            if (self.pending_len >= self.pending.len) {
                // A hostile burst overflowed the sequence buffer; drop it.
                self.pending_len = 0;
                continue;
            }
            const n = self.tty.read(self.pending[self.pending_len..]) catch
                return error.ReadFailed;
            if (n == 0) return error.EndOfStream;
            self.pending_len += n;
        }
    }
};
