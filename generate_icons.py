#!/usr/bin/env python3
# generate_icons.py — Creates placeholder PNG icons for the extension
# Run: python generate_icons.py

import struct, zlib, os

def create_png(size, color=(0, 180, 120)):
    """Create a minimal valid PNG of given size with solid color."""
    def make_chunk(chunk_type, data):
        c = chunk_type + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    # PNG signature
    sig = b'\x89PNG\r\n\x1a\n'

    # IHDR
    ihdr_data = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)

    # IDAT - image data
    raw = b''
    r, g, b = color
    for _ in range(size):
        raw += b'\x00' + bytes([r, g, b] * size)
    compressed = zlib.compress(raw)
    idat = make_chunk(b'IDAT', compressed)

    # IEND
    iend = make_chunk(b'IEND', b'')

    return sig + ihdr + idat + iend

os.makedirs('extension/icons', exist_ok=True)

# PhishGuard green color
color = (0, 180, 120)

for size in [16, 48, 128]:
    with open(f'extension/icons/icon{size}.png', 'wb') as f:
        f.write(create_png(size, color))
    print(f"Created icon{size}.png")

print("\nDone! Icons created in extension/icons/")
print("You can replace these with your own icons.")
