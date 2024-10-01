const std = @import("std");
const builtin = @import("builtin");
const log = std.log;
const Allocator = std.mem.Allocator;
const known_folders = @import("known-folders");

var log_tty_config: std.io.tty.Config = undefined; // Will be initialized immediately in main

pub const std_options: std.Options = .{
    .logFn = logImpl,
    .log_level = .info,
};

pub fn logImpl(
    comptime level: log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const prefix = if (scope == .default)
        comptime level.asText() ++ ": "
    else
        comptime level.asText() ++ "(" ++ @tagName(scope) ++ "): ";
    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const stderr = std.io.getStdErr().writer();
    log_tty_config.setColor(stderr, switch (level) {
        .err => .bright_red,
        .warn => .bright_yellow,
        .info => .bright_blue,
        .debug => .bright_magenta,
    }) catch return;
    stderr.writeAll(prefix) catch return;
    log_tty_config.setColor(stderr, .reset) catch return;
    stderr.print(format ++ "\n", args) catch return;
}

pub fn main() !u8 {
    log_tty_config = std.io.tty.detectConfig(std.io.getStdErr());

    var gpa_state: Gpa = .init;
    defer gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);
    mainInner(gpa, args) catch |err| switch (err) {
        error.ExitFailure => return 1,
        else => |other| {
            log.err("unexpected error: {}", .{other});
            // TODO: print error return trace
            return 1;
        },
    };
    return 0;
}

fn mainInner(gpa: Allocator, args: []const []const u8) !void {
    if (args.len == 0) return fatal("no program specified", .{});
    if (std.mem.eql(u8, args[0], "zig")) {
        try exeZig(gpa, args[1..]);
    } else {
        try exeZigman(gpa, args[1..]);
    }
}

const zigman_version = "0.0.0\n"; // TODO: embed from build.zig.zon

const zigman_usage =
    \\Usage: zigman COMMAND [ARGS...]
    \\
    \\Commands:
    \\  help                            Print this message
    \\  version                         Print zigman version
    \\
    \\  install [VERSION]               Install Zig VERSION (default 'latest')
    \\  list                            List installed Zig versions
    \\  run VERSION [ARGS...]           Run Zig VERSION with ARGS
    \\
;

fn exeZigman(gpa: Allocator, args: []const []const u8) !void {
    if (args.len == 0) return fatal("no command specified", .{});

    if (std.mem.eql(u8, args[0], "help")) {
        try std.io.getStdOut().writeAll(zigman_usage);
    } else if (std.mem.eql(u8, args[0], "version")) {
        try std.io.getStdOut().writeAll(zigman_version);
    } else if (std.mem.eql(u8, args[0], "install")) {
        try cmdInstall(args[1..]);
    } else if (std.mem.eql(u8, args[0], "list")) {
        try cmdList(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "run")) {
        try cmdRun(gpa, args[1..]);
    } else {
        return fatal("unrecognized command: '{s}'", .{args[0]});
    }
}

fn cmdInstall(args: []const []const u8) !void {
    _ = args;

    return fatal("TODO: implement install command", .{});
}

fn cmdList(gpa: Allocator, args: []const []const u8) !void {
    if (args.len != 0) return fatal("too many arguments", .{});

    const available = loadAvailableInstallations(gpa) catch |err|
        return fatal("failed to load Zig installations: {}", .{err});
    defer gpa.free(available);
    const tty_config = std.io.tty.detectConfig(std.io.getStdOut());
    var stdout_buf = std.io.bufferedWriter(std.io.getStdOut().writer());
    const stdout = stdout_buf.writer();
    for (available) |zig| {
        try stdout.print("{s}", .{zig.version.slice()});
        inline for (comptime std.meta.fieldNames(ZigInstallation.Flags)) |flag| {
            if (@field(zig.flags, flag)) {
                try tty_config.setColor(stdout, .bright_white);
                try stdout.writeAll(" " ++ flag);
                try tty_config.setColor(stdout, .reset);
            }
        }
        try stdout.writeByte('\n');
    }
    try stdout_buf.flush();
}

fn cmdRun(gpa: Allocator, args: []const []const u8) !noreturn {
    if (args.len == 0) return fatal("no version provided", .{});

    const query = ZigInstallation.Query.parse(args[0]);
    const available = loadAvailableInstallations(gpa) catch |err|
        return fatal("failed to load Zig installations: {}", .{err});
    defer gpa.free(available);
    const zig = findMatchingInstallation(available, query) orelse return fatal("no Zig matching '{s}'", .{args[0]});
    return execZig(gpa, zig, args[1..]);
}

fn exeZig(gpa: Allocator, args: []const []const u8) !noreturn {
    const available = loadAvailableInstallations(gpa) catch |err|
        return fatal("failed to load Zig installations: {}", .{err});
    defer gpa.free(available);
    const zig = findMatchingInstallation(available, .default) orelse return fatal("no Zig version installed", .{});
    return execZig(gpa, zig, args);
}

fn execZig(gpa: Allocator, zig: ZigInstallation, args: []const []const u8) !noreturn {
    const path = path: {
        const zig_global_cache = try getZigGlobalCacheDirPath(gpa);
        defer gpa.free(zig_global_cache);
        break :path try std.fs.path.join(gpa, &.{ zig_global_cache, "p", zig.hash.slice(), "zig" });
    };
    defer gpa.free(path);
    const argv = try gpa.alloc([]const u8, args.len + 1);
    defer gpa.free(argv);
    argv[0] = path;
    @memcpy(argv[1..], args);
    return std.process.execv(gpa, argv);
}

const ZigInstallation = struct {
    version: Version,
    hash: Hash,
    flags: Flags,

    const Version = std.BoundedArray(u8, 32);
    // Current Zig package hashes are always 68 bytes. However, if
    // https://github.com/ziglang/zig/issues/20178 is implemented, it could be
    // variable up to 75 bytes. Increasing this to 80 makes it a nice round
    // number.
    const Hash = std.BoundedArray(u8, 80);
    const Flags = packed struct {
        default: bool = false,
        master: bool = false,
        latest: bool = false,
        mach_latest: bool = false,
    };

    const Query = union(enum) {
        default,
        master,
        latest,
        exact: []const u8,
        mach_latest,
        mach_exact: []const u8,

        fn parse(s: []const u8) Query {
            if (std.mem.eql(u8, s, "default")) {
                return .default;
            } else if (std.mem.eql(u8, s, "master")) {
                return .master;
            } else if (std.mem.eql(u8, s, "latest")) {
                return .latest;
            } else if (std.mem.eql(u8, s, "mach-latest")) {
                return .mach_latest;
            } else if (std.mem.indexOf(u8, s, "mach") != null) {
                return .{ .mach_exact = s };
            } else {
                return .{ .exact = s };
            }
        }
    };

    fn parse(s: []const u8) error{InvalidInstallation}!ZigInstallation {
        var parts = std.mem.splitScalar(u8, s, ' ');
        const version = Version.fromSlice(parts.first()) catch return error.InvalidInstallation;
        const hash = hash: {
            const part = parts.next() orelse return error.InvalidInstallation;
            break :hash Hash.fromSlice(part) catch return error.InvalidInstallation;
        };
        var flags: Flags = .{};
        while (parts.next()) |part| {
            // This is a bit more complex than it needs to be due to
            // https://github.com/ziglang/zig/issues/9524
            var valid_flag = false;
            inline for (comptime std.meta.fieldNames(Flags)) |flag| {
                if (std.mem.eql(u8, part, flag)) {
                    @field(flags, flag) = true;
                    valid_flag = true;
                }
            }
            if (!valid_flag) return error.InvalidInstallation;
        }
        return .{
            .version = version,
            .hash = hash,
            .flags = flags,
        };
    }

    test parse {
        try std.testing.expectEqualDeep(ZigInstallation{
            .version = Version.fromSlice("0.13.0") catch unreachable,
            .hash = Hash.fromSlice("122095c9b2703250317da71eb14a2979a398ec776b42a979d5ffbf0cc5100a77e36b") catch unreachable,
            .flags = .{
                .default = true,
                .latest = true,
            },
        }, try ZigInstallation.parse("0.13.0 122095c9b2703250317da71eb14a2979a398ec776b42a979d5ffbf0cc5100a77e36b default latest"));
    }

    fn write(zig: ZigInstallation, writer: anytype) !void {
        try writer.format("{s} {s}", .{ zig.version.slice(), zig.hash.slice() });
        inline for (std.meta.fieldNames(Flags)) |flag| {
            if (@field(zig.flags, flag)) {
                try writer.writeAll(" " ++ flag);
            }
        }
    }
};

fn loadAvailableInstallations(gpa: Allocator) ![]ZigInstallation {
    var file = file: {
        var data_dir = try makeOpenAppDir(gpa, .data);
        defer data_dir.close();
        break :file data_dir.openFile("available", .{}) catch |err| switch (err) {
            error.FileNotFound => return &.{},
            else => |other| return other,
        };
    };
    defer file.close();
    var br = std.io.bufferedReader(file.reader());
    const reader = br.reader();

    var available: std.ArrayList(ZigInstallation) = .init(gpa);
    defer available.deinit();
    var buf: [256]u8 = undefined; // enough to hold any valid line
    while (reader.readUntilDelimiter(&buf, '\n')) |line| {
        try available.append(try .parse(line));
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.StreamTooLong => return error.InvalidInstallation,
        else => |other| return other,
    }
    return try available.toOwnedSlice();
}

fn saveAvailableInstallations(gpa: Allocator, available: []const ZigInstallation) !void {
    var file = file: {
        var data_dir = try makeOpenAppDir(gpa, .data);
        defer data_dir.close();
        break :file try data_dir.createFile("available", .{});
    };
    defer file.close();
    var bw = std.io.bufferedWriter(file.writer());
    const writer = bw.writer();
    for (available) |zig| {
        try zig.write(writer);
        try writer.writeByte('\n');
    }
}

fn findMatchingInstallation(available: []const ZigInstallation, query: ZigInstallation.Query) ?ZigInstallation {
    return switch (query) {
        .default => for (available) |zig| {
            if (zig.flags.default) break zig;
        } else null,
        .master => for (available) |zig| {
            if (zig.flags.master) break zig;
        } else null,
        .latest => for (available) |zig| {
            if (zig.flags.latest) break zig;
        } else null,
        .mach_latest => for (available) |zig| {
            if (zig.flags.mach_latest) break zig;
        } else null,
        .exact, .mach_exact => |version| for (available) |zig| {
            if (std.mem.eql(u8, version, zig.version.slice())) break zig;
        } else null,
    };
}

fn makeOpenAppDir(gpa: Allocator, known_folder: known_folders.KnownFolder) !std.fs.Dir {
    var parent_dir = try known_folders.open(gpa, known_folder, .{}) orelse return error.FileNotFound;
    defer parent_dir.close();
    return try parent_dir.makeOpenPath("zigman", .{});
}

fn getZigGlobalCacheDirPath(gpa: Allocator) ![]u8 {
    // Copied from https://github.com/ziglang/zig/blob/3b465ebec59ee942b6c490ada2f81902ec047d7f/src/introspect.zig#L82-L103

    if (try std.zig.EnvVar.ZIG_GLOBAL_CACHE_DIR.get(gpa)) |value| return value;

    const appname = "zig";

    if (builtin.os.tag != .windows) {
        if (std.zig.EnvVar.XDG_CACHE_HOME.getPosix()) |cache_root| {
            if (cache_root.len > 0) {
                return std.fs.path.join(gpa, &[_][]const u8{ cache_root, appname });
            }
        }
        if (std.zig.EnvVar.HOME.getPosix()) |home| {
            return std.fs.path.join(gpa, &[_][]const u8{ home, ".cache", appname });
        }
    }

    return std.fs.getAppDataDir(gpa, appname);
}

fn fatal(comptime fmt: []const u8, args: anytype) error{ExitFailure} {
    log.err(fmt, args);
    return error.ExitFailure;
}

/// Workaround for https://github.com/ziglang/zig/issues/12484
const Gpa = if (builtin.mode == .Debug)
    struct {
        state: std.heap.GeneralPurposeAllocator(.{}),

        const init: Gpa = .{ .state = .init };

        fn allocator(gpa: *Gpa) Allocator {
            return gpa.state.allocator();
        }

        fn deinit(gpa: *Gpa) void {
            _ = gpa.state.deinit();
        }
    }
else
    struct {
        const init: Gpa = .{};

        fn allocator(_: *Gpa) Allocator {
            return std.heap.c_allocator;
        }

        fn deinit(_: *Gpa) void {}
    };

test {
    _ = ZigInstallation;
}
