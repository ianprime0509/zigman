const std = @import("std");
const builtin = @import("builtin");
const log = std.log;
const Allocator = std.mem.Allocator;
const known_folders = @import("known-folders");

var log_tty_config: std.io.tty.Config = undefined; // will be initialized immediately in main

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
            const maybe_error_trace = @errorReturnTrace();
            log.err("unexpected error: {}", .{other});
            if (maybe_error_trace) |error_trace| std.debug.dumpStackTrace(error_trace.*);
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
    \\
    \\  default VERSION                 Set Zig VERSION as the default
    \\  graft PATH                      Grafts/copies an existing Zig at PATH into Zigman
    \\  install [VERSION]               Install Zig VERSION (default 'latest')
    \\  list                            List installed Zig versions
    \\  prune                           Removes old Zig masters
    \\  remove VERSION                  Remove Zig VERSION
    \\
    \\  run VERSION [ARGS...]           Run Zig VERSION with ARGS
    \\
    \\  help                            Print this message
    \\  version                         Print zigman version
    \\
;

fn exeZigman(gpa: Allocator, args: []const []const u8) !void {
    if (args.len == 0) return fatal("no command specified", .{});

    if (std.mem.eql(u8, args[0], "default")) {
        try cmdDefault(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "graft")) {
        try cmdGraft(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "install")) {
        try cmdInstall(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "list")) {
        try cmdList(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "prune")) {
        try cmdPrune(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "remove")) {
        try cmdRemove(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "run")) {
        try cmdRun(gpa, args[1..]);
    } else if (std.mem.eql(u8, args[0], "help")) {
        try std.io.getStdOut().writeAll(zigman_usage);
    } else if (std.mem.eql(u8, args[0], "version")) {
        try std.io.getStdOut().writeAll(zigman_version);
    } else {
        return fatal("unrecognized command: '{s}'", .{args[0]});
    }
}

fn cmdDefault(gpa: Allocator, args: []const []const u8) !void {
    if (args.len == 0) return fatal("no version provided", .{});
    if (args.len > 1) return fatal("too many arguments", .{});

    var data = try AppData.open(gpa);
    defer data.close();
    const available = try data.loadAvailableInstallations(gpa);
    defer gpa.free(available);
    const new_default = ZigInstallation.Query.parse(args[0]) catch
        return fatal("invalid Zig version", .{});
    if (findMatchingInstallationIndex(available, new_default) == null) {
        return fatal("no matching Zig version installed", .{});
    }
    try data.saveDefault(new_default);
}

fn cmdGraft(gpa: Allocator, args: []const []const u8) !void {
    if (args.len == 0) return fatal("no path provided", .{});
    if (args.len > 1) return fatal("too many arguments", .{});

    try graftZig(gpa, args[0]);
}

fn cmdInstall(gpa: Allocator, args: []const []const u8) !void {
    _ = gpa;
    _ = args;

    return fatal("TODO: implement install command", .{});
}

fn cmdList(gpa: Allocator, args: []const []const u8) !void {
    if (args.len != 0) return fatal("too many arguments", .{});

    var data = try AppData.open(gpa);
    defer data.close();
    const available = try data.loadAvailableInstallations(gpa);
    defer gpa.free(available);
    std.sort.pdq(ZigInstallation, available, {}, struct {
        fn lessThan(ctx: void, lhs: ZigInstallation, rhs: ZigInstallation) bool {
            _ = ctx;
            const lhs_version = lhs.semanticVersion();
            const lhs_is_mach = std.mem.startsWith(u8, lhs_version.pre orelse "", "mach");
            const rhs_version = rhs.semanticVersion();
            const rhs_is_mach = std.mem.startsWith(u8, rhs_version.pre orelse "", "mach");
            if (!lhs_is_mach and rhs_is_mach) return true;
            if (lhs_is_mach and !rhs_is_mach) return false;
            return lhs_version.order(rhs_version) == .gt;
        }
    }.lessThan);
    const master_index = findMatchingInstallationIndex(available, .master);
    const latest_index = findMatchingInstallationIndex(available, .latest);
    const mach_latest_index = findMatchingInstallationIndex(available, .mach_latest);
    const default_index = if (try data.loadDefault()) |default|
        findMatchingInstallationIndex(available, default)
    else
        null;

    const tty_config = std.io.tty.detectConfig(std.io.getStdOut());
    var stdout_buf = std.io.bufferedWriter(std.io.getStdOut().writer());
    const stdout = stdout_buf.writer();
    for (available, 0..) |zig, i| {
        try stdout.print("{s}", .{zig.version.slice()});
        if (i == master_index) {
            try tty_config.setColor(stdout, .bright_white);
            try stdout.writeAll(" master");
            try tty_config.setColor(stdout, .reset);
        }
        if (i == latest_index) {
            try tty_config.setColor(stdout, .bright_white);
            try stdout.writeAll(" latest");
            try tty_config.setColor(stdout, .reset);
        }
        if (i == mach_latest_index) {
            try tty_config.setColor(stdout, .bright_white);
            try stdout.writeAll(" mach-latest");
            try tty_config.setColor(stdout, .reset);
        }
        if (i == default_index) {
            try tty_config.setColor(stdout, .bright_white);
            try stdout.writeAll(" default");
            try tty_config.setColor(stdout, .reset);
        }
        try stdout.writeByte('\n');
    }
    try stdout_buf.flush();
}

fn cmdPrune(gpa: Allocator, args: []const []const u8) !void {
    _ = gpa;
    _ = args;

    return fatal("TODO: implement prune command", .{});
}

fn cmdRemove(gpa: Allocator, args: []const []const u8) !void {
    if (args.len == 0) return fatal("no version provided", .{});
    if (args.len > 1) return fatal("too many arguments", .{});

    var data = try AppData.open(gpa);
    defer data.close();
    const available = try data.loadAvailableInstallations(gpa);
    defer gpa.free(available);
    const query = ZigInstallation.Query.parse(args[0]) catch
        return fatal("invalid Zig version", .{});
    const remove_index = findMatchingInstallationIndex(available, query) orelse
        return fatal("no Zig matching '{s}'", .{args[0]});
    const new_available = try gpa.alloc(ZigInstallation, available.len - 1);
    defer gpa.free(new_available);
    @memcpy(new_available[0..remove_index], available[0..remove_index]);
    @memcpy(new_available[remove_index..], available[remove_index + 1 ..]);
    try data.saveAvailableInstallations(new_available);
}

fn cmdRun(gpa: Allocator, args: []const []const u8) !noreturn {
    if (args.len == 0) return fatal("no version provided", .{});

    var data = try AppData.open(gpa);
    defer data.close();
    const available = try data.loadAvailableInstallations(gpa);
    defer gpa.free(available);
    const query = query: {
        if (std.mem.eql(u8, args[0], "default")) {
            break :query try data.loadDefault() orelse return fatal("no default Zig version", .{});
        } else {
            break :query ZigInstallation.Query.parse(args[0]) catch return fatal("invalid Zig version", .{});
        }
    };
    const zig_index = findMatchingInstallationIndex(available, query) orelse
        return fatal("no Zig matching '{s}'", .{args[0]});
    try execZig(gpa, available[zig_index], args[1..]);
}

fn exeZig(gpa: Allocator, args: []const []const u8) !noreturn {
    var data = try AppData.open(gpa);
    defer data.close();
    const available = try data.loadAvailableInstallations(gpa);
    defer gpa.free(available);
    const default = try data.loadDefault() orelse return fatal("no default Zig version", .{});
    const zig_index = findMatchingInstallationIndex(available, default) orelse
        return fatal("no Zig version matching default '{}'", .{default});
    try execZig(gpa, available[zig_index], args);
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
    const err = std.process.execv(gpa, argv);
    return fatal("failed to run Zig {s}: {}", .{ zig.version.slice(), err });
}

fn graftZig(gpa: Allocator, path: []const u8) !void {
    const exe_path = try std.fs.path.join(gpa, &.{ path, "zig" });
    defer gpa.free(exe_path);
    const raw_version = try runProcess(gpa, &.{ exe_path, "version" });
    defer gpa.free(raw_version);
    const version = std.mem.trimRight(u8, raw_version, "\r\n");
    const raw_hash = try runProcess(gpa, &.{ exe_path, "fetch", path });
    defer gpa.free(raw_hash);
    const hash = std.mem.trimRight(u8, raw_hash, "\r\n");
    const new_zig = ZigInstallation.init(version, hash) catch
        return fatal("invalid Zig version '{s}', hash '{s}'", .{ version, hash });

    var data = try AppData.open(gpa);
    defer data.close();
    const available = try data.loadAvailableInstallations(gpa);
    defer gpa.free(available);
    if (findMatchingInstallationIndex(available, .{ .exact = new_zig.version })) |existing_index| {
        const existing_zig = available[existing_index];
        if (!std.mem.eql(u8, existing_zig.hash.slice(), hash)) {
            return fatal("Zig '{s}' is already installed with conflicting hash", .{version});
        }
        return; // already present in available installations
    }
    const new_available = try gpa.alloc(ZigInstallation, available.len + 1);
    defer gpa.free(new_available);
    @memcpy(new_available[0..available.len], available);
    new_available[available.len] = new_zig;
    try data.saveAvailableInstallations(new_available);
}

fn runProcess(gpa: Allocator, argv: []const []const u8) ![]u8 {
    var child = std.process.Child.init(argv, gpa);
    child.stdout_behavior = .Pipe;
    child.spawn() catch |err| return fatal("failed to spawn process '{}': {}", .{ fmtArgv(argv), err });
    // 1024 bytes is more than enough for any output we will be using this function to get.
    const stdout = child.stdout.?.readToEndAlloc(gpa, 1024) catch |err|
        return fatal("failed to read output of process '{}': {}", .{ fmtArgv(argv), err });
    errdefer gpa.free(stdout);
    const term = child.wait() catch |err|
        return fatal("failed to execute process '{}': {}", .{ fmtArgv(argv), err });
    switch (term) {
        .Exited => |status| {
            if (status != 0) {
                return fatal("process '{}' exited with non-zero status: {}", .{ fmtArgv(argv), status });
            }
        },
        .Signal => |signal| return fatal("process '{}' termiated with signal: {}", .{ fmtArgv(argv), signal }),
        .Stopped => |code| return fatal("process '{}' stopped with code: {}", .{ fmtArgv(argv), code }),
        .Unknown => |code| return fatal("process '{}' terminated for unknown reason: {}", .{ fmtArgv(argv), code }),
    }
    return stdout;
}

fn fmtArgv(argv: []const []const u8) std.fmt.Formatter(formatArgv) {
    return .{ .data = argv };
}

fn formatArgv(
    argv: []const []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    for (argv, 0..) |arg, i| {
        if (i > 0) try writer.writeByte(' ');
        try writer.writeAll(arg);
    }
}

const AppData = struct {
    dir: std.fs.Dir,

    fn open(gpa: Allocator) !AppData {
        var parent_dir = try known_folders.open(gpa, .data, .{}) orelse return error.FileNotFound;
        defer parent_dir.close();
        return .{ .dir = try parent_dir.makeOpenPath("zigman", .{}) };
    }

    fn close(data: *AppData) void {
        data.dir.close();
        data.* = undefined;
    }

    fn loadDefault(data: *AppData) !?ZigInstallation.Query {
        var file = data.dir.openFile("default", .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => |other| return other,
        };
        defer file.close();
        var buf: [ZigInstallation.max_version_len + 2]u8 = undefined;
        var len = try file.readAll(&buf);
        if (len > 0 and buf[len - 1] == '\n') len -= 1;
        return try .parse(buf[0..len]);
    }

    fn saveDefault(data: *AppData, default: ZigInstallation.Query) !void {
        var file = try data.dir.createFile("default", .{});
        defer file.close();
        try file.writer().print("{}\n", .{default});
        try file.sync();
    }

    fn loadAvailableInstallations(data: *AppData, gpa: Allocator) ![]ZigInstallation {
        var file = data.dir.openFile("available", .{}) catch |err| switch (err) {
            error.FileNotFound => return &.{},
            else => |other| return other,
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

    fn saveAvailableInstallations(data: *AppData, available: []const ZigInstallation) !void {
        var file = try data.dir.createFile("available", .{});
        defer file.close();
        var bw = std.io.bufferedWriter(file.writer());
        const writer = bw.writer();
        for (available) |zig| {
            try writer.print("{}\n", .{zig});
        }
        try bw.flush();
        try file.sync();
    }
};

const ZigInstallation = struct {
    version: Version,
    hash: Hash,

    const max_version_len = 32;
    const Version = std.BoundedArray(u8, max_version_len);
    // Current Zig package hashes are always 68 bytes. However, if
    // https://github.com/ziglang/zig/issues/20178 is implemented, it could be
    // variable up to 75 bytes. Increasing this to 80 makes it a nice round
    // number.
    const max_hash_len = 80;
    const Hash = std.BoundedArray(u8, max_hash_len);

    const Query = union(enum) {
        master,
        latest,
        mach_latest,
        exact: Version,

        fn parse(s: []const u8) error{InvalidInstallation}!Query {
            if (std.mem.eql(u8, s, "master")) {
                return .master;
            } else if (std.mem.eql(u8, s, "latest")) {
                return .latest;
            } else if (std.mem.eql(u8, s, "mach-latest")) {
                return .mach_latest;
            } else {
                const version = Version.fromSlice(s) catch return error.InvalidInstallation;
                _ = std.SemanticVersion.parse(version.slice()) catch return error.InvalidInstallation;
                return .{ .exact = version };
            }
        }

        fn unparse(query: Query) []const u8 {
            return switch (query) {
                .master => "master",
                .latest => "latest",
                .mach_latest => "mach-latest",
                .exact => |version| version.slice(),
            };
        }

        pub fn format(
            query: Query,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = fmt;
            _ = options;
            try writer.writeAll(query.unparse());
        }
    };

    fn semanticVersion(zig: *const ZigInstallation) std.SemanticVersion {
        // The semantic version validity is verified in `init`.
        // Note the *const parameter, because the parsed SemanticVersion
        // contains pointers to the memory in `zig`.
        return std.SemanticVersion.parse(zig.version.slice()) catch unreachable;
    }

    fn init(version: []const u8, hash: []const u8) error{InvalidInstallation}!ZigInstallation {
        _ = std.SemanticVersion.parse(version) catch return error.InvalidInstallation;
        return .{
            .version = Version.fromSlice(version) catch return error.InvalidInstallation,
            .hash = Hash.fromSlice(hash) catch return error.InvalidInstallation,
        };
    }

    fn parse(s: []const u8) error{InvalidInstallation}!ZigInstallation {
        var parts = std.mem.splitScalar(u8, s, ' ');
        const version = parts.first();
        const hash = parts.next() orelse return error.InvalidInstallation;
        if (parts.next() != null) return error.InvalidInstallation;
        return init(version, hash);
    }

    test parse {
        try std.testing.expectEqualDeep(ZigInstallation{
            .version = Version.fromSlice("0.13.0") catch unreachable,
            .hash = Hash.fromSlice("122095c9b2703250317da71eb14a2979a398ec776b42a979d5ffbf0cc5100a77e36b") catch unreachable,
        }, try ZigInstallation.parse("0.13.0 122095c9b2703250317da71eb14a2979a398ec776b42a979d5ffbf0cc5100a77e36b"));
    }

    pub fn format(
        zig: ZigInstallation,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = fmt;
        _ = options;
        try writer.print("{s} {s}", .{ zig.version.slice(), zig.hash.slice() });
    }
};

fn findMatchingInstallationIndex(available: []const ZigInstallation, query: ZigInstallation.Query) ?usize {
    switch (query) {
        .master => {
            return findNewestInstallationIndexMatching(available, struct {
                fn isApplicable(version: std.SemanticVersion) bool {
                    return std.mem.startsWith(u8, version.pre orelse "", "dev.");
                }
            }.isApplicable);
        },
        .latest => {
            return findNewestInstallationIndexMatching(available, struct {
                fn isApplicable(version: std.SemanticVersion) bool {
                    return version.pre == null and version.build == null;
                }
            }.isApplicable);
        },
        .mach_latest => {
            return findNewestInstallationIndexMatching(available, struct {
                fn isApplicable(version: std.SemanticVersion) bool {
                    return std.mem.eql(u8, version.pre orelse "", "mach");
                }
            }.isApplicable);
        },
        .exact => |version| {
            return for (available, 0..) |zig, i| {
                if (std.mem.eql(u8, version.slice(), zig.version.slice())) break i;
            } else null;
        },
    }
}

fn findNewestInstallationIndexMatching(available: []const ZigInstallation, isApplicable: *const fn (std.SemanticVersion) bool) ?usize {
    var latest: ?struct { std.SemanticVersion, usize } = null;
    for (available, 0..) |*zig, i| {
        const zig_version = zig.semanticVersion();
        if (isApplicable(zig_version) and (latest == null or latest.?[0].order(zig_version) == .lt)) {
            latest = .{ zig_version, i };
        }
    }
    return if (latest) |found| found[1] else null;
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
