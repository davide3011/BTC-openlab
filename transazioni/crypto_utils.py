import hashlib
from ecdsa import SECP256k1

def sha256d(b: bytes) -> bytes:
    """Doppio SHA256 (SHA256(SHA256(data)))"""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def vi(n: int) -> bytes:
    """Codifica VarInt per Bitcoin"""
    if n < 0xfd:
        return n.to_bytes(1, "little")
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def read_varint(b: bytes, i: int):
    """Legge un VarInt da bytes a partire dalla posizione i"""
    prefix = b[i]
    i += 1
    if prefix < 0xfd:
        return prefix, i
    if prefix == 0xfd:
        val = int.from_bytes(b[i:i+2], "little")
        i += 2
        return val, i
    if prefix == 0xfe:
        val = int.from_bytes(b[i:i+4], "little")
        i += 4
        return val, i
    val = int.from_bytes(b[i:i+8], "little")
    i += 8
    return val, i

def der_low_s(r: int, s: int) -> bytes:
    """Crea firma DER normalizzata secondo BIP-62 (low-s)"""
    n = SECP256k1.order
    if s > n // 2:
        s = n - s
    
    rb = r.to_bytes((r.bit_length() + 7) // 8, "big")
    sb = s.to_bytes((s.bit_length() + 7) // 8, "big")
    
    # Padding per evitare interpretazione come numero negativo
    if rb and (rb[0] & 0x80):
        rb = b"\x00" + rb
    if sb and (sb[0] & 0x80):
        sb = b"\x00" + sb
    
    return (
        b"\x30" + bytes([len(rb) + len(sb) + 4]) +
        b"\x02" + bytes([len(rb)]) + rb +
        b"\x02" + bytes([len(sb)]) + sb
    )

def little_endian(h: str) -> bytes:
    """Converte hex string in bytes little-endian"""
    return bytes.fromhex(h)[::-1]

# Funzioni Bech32
def bech32_polymod(values):
    """Calcola il polymod per bech32"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= GEN[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Espande l'HRP per il calcolo del checksum bech32"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    """Verifica il checksum bech32"""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(bech):
    """Decodifica un indirizzo bech32"""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or pos + 1 + 6 > len(bech):
        return (None, None)
    
    if not all(x in "qpzry9x8gf2tvdw0s3jn54khce6mua7l" for x in bech[pos+1:]):
        return (None, None)
    
    hrp = bech[:pos]
    data = ["qpzry9x8gf2tvdw0s3jn54khce6mua7l".find(x) for x in bech[pos+1:]]
    
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    
    return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
    """Converte tra diverse basi di bit per bech32"""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    
    return ret

def decode_bech32_address(addr):
    """Decodifica un indirizzo bech32 e restituisce l'hash160"""
    hrp, data = bech32_decode(addr)
    if hrp is None:
        return None
    
    if len(data) < 1:
        return None
    
    witver = data[0]
    if witver > 16:
        return None
    
    spec = convertbits(data[1:], 5, 8, False)
    if spec is None or len(spec) < 2 or len(spec) > 40:
        return None
    
    if witver == 0 and len(spec) != 20 and len(spec) != 32:
        return None
    
    return bytes(spec)

def scripthash_from_spk(spk: bytes) -> str:
    """Calcola lo scripthash per Electrum/Fulcrum da scriptPubKey"""
    return hashlib.sha256(spk).digest()[::-1].hex()