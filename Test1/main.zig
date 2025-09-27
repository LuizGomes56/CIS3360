const std = @import("std");

pub fn vigenere(allocator: std.mem.Allocator, plaintext: []const u8, keyword: []const u8) !void {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try buffer.appendSlice(plaintext);

    while (buffer.items.len % keyword.len != 0) {
        try buffer.append('X');
    }

    var keyword_extended = std.ArrayList(u8).init(allocator);
    defer keyword_extended.deinit();

    for (0..(buffer.items.len / keyword.len)) |_| {
        try keyword_extended.appendSlice(keyword);
    }

    var ciphertext = std.ArrayList(u8).init(allocator);

    for (0..keyword_extended.items.len) |i| {
        try ciphertext.append(((buffer.items[i] + keyword_extended.items[i] - ('A' << 1)) % 26) + 'A');
    }

    std.debug.print("ciphertext: {s}\n", .{ciphertext.items});
}

pub fn cbc(allocator: std.mem.Allocator, plaintext: u128, size: usize, iv: u8) !void {
    // split plaintext into chunks of exact size
    var chunks = std.ArrayList([]const u8).init(allocator);
    defer chunks.deinit();

    for (0..plaintext / size) |i| {
        try chunks.append(plaintext[i * size .. (i + 1) * size]);
    }

    // xor each chunk with the previous chunk
    var ciphertext = std.ArrayList(u8).init(allocator);
    defer ciphertext.deinit();

    try ciphertext.appendSlice(chunks.items[0] ^ iv);

    for (1..chunks.items.len) |i| {
        var chunk = std.ArrayList(u8).init(allocator);
        defer chunk.deinit();

        try chunk.appendSlice(chunks.items[i]);

        for (0..chunk.items.len) |j| {
            chunk.items[j] = chunk.items[j] ^ ciphertext.items[i * size + j];
        }

        try ciphertext.appendSlice(chunk.items);
    }

    std.debug.print("cbc ciphertext: {s}\n", .{ciphertext.items});
}

pub fn ecp(allocator: std.mem.Allocator, bit_string: []const u1, block_size: u8) !void {
    var buffer = std.ArrayList(u4).init(allocator);
    defer buffer.deinit();

    for (0..bit_string.len / block_size) |i| {
        var half_byte: u4 = 0;
        for (0..block_size) |j| {
            half_byte = (half_byte << 1) | @as(u4, bit_string[i * block_size + j]);
        }
        half_byte = ~half_byte;
        half_byte <<= 1;
        try buffer.append(half_byte);
    }

    for (buffer.items) |item| {
        std.debug.print("{b:0>4} ", .{item});
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    // get key length, then add X to the plaintext until it has a multiple of key len
    // after, create a string of key repeated. Then sum the indexof char for each.
    // the final result is the ciphertext
    try vigenere(allocator, "STORMYNIGHT", "ROCK");
    // Take n bits of a string, pass a block size to divide them into chunks.
    // divide each chunk, flip the bits using NOT, then left shift 1.
    // then concatenate chunks of {BLOCK_SIZE} bits, and this is the ciphertext (bin)
    try ecp(allocator, &[_]u1{ 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0 }, 4);

    // ECB is the same as vigenere, but chunking (A block size is passed as well)

    // CBC has plaintext, IV, size;
    // chunk plaintext into size chunks
    // take chunk Zero, XOR IV, then flip bits and shift left;
    // with the result of this operation, take chunk 1 and XOR with it; repeat cycle.
    try cbc(allocator, 0b110110100110, 4, 'A');
}
