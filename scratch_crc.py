import zlib, struct

def patch_file(data, patch_data):
    idx = 0
    while idx < len(patch_data):
        address = struct.unpack('>I', patch_data[idx:idx+4])[0]
        idx += 4
        if address == 0xFFFFFFFF:
            break
        amount = struct.unpack('>I', patch_data[idx:idx+4])[0]
        idx += 4
        for _ in range(amount):
            word = patch_data[idx:idx+4]
            data[address:address+4] = word
            address += 4
            idx += 4
    return data

cbb = bytearray(open('standalone/17559/../common/SE_17489.bin', 'rb').read())
patch = open('standalone/17559/bin/patches_g2trinity.bin', 'rb').read()

import io
f = io.BytesIO(patch)
cb_patch = bytearray()
while True:
    try:
        address = f.read(4)
        if not address: break
        addr_val = struct.unpack('>I', address)[0]
        cb_patch += address
        if addr_val == 0xFFFFFFFF:
            break
        amt = f.read(4)
        amount = struct.unpack('>I', amt)[0]
        cb_patch += amt
        cb_patch += f.read(amount * 4)
    except: break

def print_crc(name, data):
    h = hex(zlib.crc32(data) & 0xFFFFFFFF)
    print(f'{name:30} {h}')
    if h == '0xfebb1074':
        print('^^^^ THIS IS IT ^^^^')

cbb_patched = patch_file(cbb[:], cb_patch)

print_crc('Unpatched Full', cbb)
z1 = cbb[:]
z1[0x10:0x20] = b'\x00'*16
print_crc('Unpatched Zeroed 0x10..0x20', z1)

print_crc('Patched Full', cbb_patched)

# Apply xeBuild logic to PATCHED:
z2 = cbb_patched[:]
z2[0x10:0x20] = b'\x00'*16
print_crc('Patched Zeroed 0x10..0x20', z2)

# Maybe CB_B nonce is at the END of CB_A? No, CB_B is just a file.
# Maybe xeBuild patches ALL files first before hashing?

# let's try just skipping the first 16 bytes?
z3 = cbb[:]
z3[:0x10] = b'\x00'*16
print_crc('Unpatched Zeroed 0..0x10', z3)

# Search for the exact patch string if any
