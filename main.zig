const std = @import("std");
const crypto = std.crypto;
const chacha_poly = crypto.aead.chacha_poly.XChaCha20Poly1305;
const argon2 = crypto.pwhash.argon2;
const salt_len = 16;
const plain_chunk_len = 4096;

fn chunk_nonce(base_nonce: [chacha_poly.nonce_length]u8, counter: u64) [chacha_poly.nonce_length]u8 {
    var n = base_nonce;
    var counter_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter_bytes, counter, .little);
    for (0..8) |i| n[n.len - 8 + i] ^= counter_bytes[i];
    return n;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len != 5) {
        std.log.err("invalid arguments", .{});
        std.log.info("usage: {s} [-e | -d] <file> -p <password>", .{args[0]});
        std.process.exit(1);
    }

    if (std.mem.eql(u8, args[1], "-e")) {
        const file_name = args[2];
        std.log.info("encrypting {s}...", .{file_name});

        var out_name: [260]u8 = undefined;

        const out_name_slice = try std.fmt.bufPrint(&out_name, "{s}.enc", .{file_name});

        if (std.mem.eql(u8, args[3], "-p")) {
            const password = args[4];
            std.log.info("using password {s}...", .{password});
            const success: bool = try encrypt_file(init, file_name, out_name_slice, password);
            if (success) {
                std.log.info("{s} \x1b[32m->\x1b[0m {s}", .{file_name, out_name_slice});
            } else {
                std.log.err("{s} failed!", .{file_name});
            }
        } else {
            std.log.err("no password provided.", .{});
            std.log.info("usage: {s} [-e | -d] <file> -p <password>", .{args[0]});
            std.process.exit(1);
        }
    } else if (std.mem.eql(u8, args[1], "-d")) {
        const file_name = args[2];
        std.log.info("decrypting {s}...", .{file_name});

        if (std.mem.eql(u8, args[3], "-p")) {
            const password = args[4];
            std.log.info("using password {s}...", .{password});
            const out_name = file_name[0..file_name.len - 4];
            const success: bool = try decrypt_file(init, file_name, out_name, password);
            if (success) {
                std.log.info("{s} \x1b[32m->\x1b[0m {s}", .{file_name, out_name});
            } else {
                std.log.err("{s} failed!", .{file_name});
            }
        } else {
            std.log.err("no password provided.", .{});
            std.log.info("usage: {s} [-e | -d] <file> -p <password>", .{args[0]});
            std.process.exit(1);
        }
    } else {
        std.log.err("invalid arguments", .{});
        std.log.info("usage: {s} [-e | -d] <file> -p <password>", .{args[0]});
        std.process.exit(1);
    }
}

fn encrypt_file(init: std.process.Init, input: []const u8, output: []const u8, password: []const u8) !bool {
    const rng_impl: std.Random.IoSource = .{.io = init.io};
    const rand = rng_impl.interface();

    var dir = std.Io.Dir.cwd();
    var in_file = try dir.openFile(init.io, input, .{ .mode = .read_only });
    defer in_file.close(init.io);

    var out_file = try dir.createFile(init.io, output, .{});
    defer out_file.close(init.io);

    var read_buf: [4096]u8 = undefined;
    var file_reader = in_file.reader(init.io, &read_buf);
    const reader = &file_reader.interface;

    var write_buf: [4096]u8 = undefined;
    var file_writer = out_file.writer(init.io, &write_buf);
    const writer = &file_writer.interface;

    var salt: [salt_len]u8 = undefined;
    var base_nonce: [chacha_poly.nonce_length]u8 = undefined;

    rand.bytes(&salt);
    rand.bytes(&base_nonce);

    var key = try derive_key(init.io, init.arena.allocator(), password, &salt);
    defer crypto.secureZero(u8, &key);

    try writer.writeAll(&salt);
    try writer.writeAll(&base_nonce);

    var chunk: [plain_chunk_len]u8 = undefined;
    var cipher_chunk: [plain_chunk_len]u8 = undefined;
    var tag: [chacha_poly.tag_length]u8 = undefined;
    var counter: u64 = 0;
    while (true) {
        const n = try reader.readSliceShort(&chunk);
        if (n == 0) break;

        const nonce = chunk_nonce(base_nonce, counter);
        chacha_poly.encrypt(cipher_chunk[0..n], &tag, chunk[0..n], &.{}, nonce, key);

        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, @intCast(n), .little);
        try writer.writeAll(&len_bytes);

        try writer.writeAll(cipher_chunk[0..n]);
        try writer.writeAll(&tag);

        counter += 1;
        if (n < chunk.len) break;
    }

    try writer.flush();

    return true;
}

fn decrypt_file(init: std.process.Init, input: []const u8, output: []const u8, password: []const u8) !bool {
    var dir = std.Io.Dir.cwd();
    var in_file = try dir.openFile(init.io, input, .{ .mode = .read_only });
    defer in_file.close(init.io);

    var out_file = try dir.createFile(init.io, output, .{});
    defer out_file.close(init.io);

    var read_buf: [4096]u8 = undefined;
    var file_reader = in_file.reader(init.io, &read_buf);
    const reader = &file_reader.interface;

    var write_buf: [4096]u8 = undefined;
    var file_writer = out_file.writer(init.io, &write_buf);
    const writer = &file_writer.interface;

    var salt: [salt_len]u8 = undefined;
    var base_nonce: [chacha_poly.nonce_length]u8 = undefined;
    try reader.readSliceAll(&salt);
    try reader.readSliceAll(&base_nonce);

    var key = try derive_key(init.io, init.arena.allocator(), password, &salt);
    defer crypto.secureZero(u8, &key);

    var plain_chunk: [plain_chunk_len]u8 = undefined;
    var cipher_chunk: [plain_chunk_len]u8 = undefined;
    var tag: [chacha_poly.tag_length]u8 = undefined;
    var counter: u64 = 0;
    while (true) {
        var len_bytes: [4]u8 = undefined;
        const header_n = try reader.readSliceShort(&len_bytes);
        if (header_n == 0) break;
        if (header_n != 4) return error.EndOfStream;
    
        const n = std.mem.readInt(u32, &len_bytes, .little);
        try reader.readSliceAll(cipher_chunk[0..n]);
        try reader.readSliceAll(&tag);
    
        const nonce = chunk_nonce(base_nonce, counter);
        chacha_poly.decrypt(plain_chunk[0..n], cipher_chunk[0..n], tag, &.{}, nonce, key) catch |err| {
            std.log.err("wrong password", .{});
            return err;
        };
    
        try writer.writeAll(plain_chunk[0..n]);
    
        counter += 1;
        if (n < plain_chunk_len) break;
    }

    try writer.flush();

    return true;
}

fn derive_key(io: std.Io, allocator: std.mem.Allocator, password: []const u8, salt: []const u8) ![chacha_poly.key_length]u8 {
    var key: [chacha_poly.key_length]u8 = undefined;
    try argon2.kdf(
        allocator,
        &key,
        password,
        salt,
        argon2.Params.interactive_2id,
        .argon2id,
        io
    );
    return key;
}
