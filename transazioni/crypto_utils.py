import hashlib
import struct
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

def bech32m_verify_checksum(hrp, data):
    """Verifica il checksum bech32m (per Taproot)"""
    const = 0x2bc830a3
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == const

def bech32_decode(bech):
    """Decodifica un indirizzo bech32/bech32m"""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None, None)
    
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or pos + 1 + 6 > len(bech):
        return (None, None, None)
    
    if not all(x in "qpzry9x8gf2tvdw0s3jn54khce6mua7l" for x in bech[pos+1:]):
        return (None, None, None)
    
    hrp = bech[:pos]
    data = ["qpzry9x8gf2tvdw0s3jn54khce6mua7l".find(x) for x in bech[pos+1:]]
    
    # Prova prima bech32
    if bech32_verify_checksum(hrp, data):
        return (hrp, data[:-6], "bech32")
    
    # Poi prova bech32m
    if bech32m_verify_checksum(hrp, data):
        return (hrp, data[:-6], "bech32m")
    
    return (None, None, None)

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
    """Decodifica un indirizzo bech32/bech32m e restituisce i dati witness"""
    hrp, data, encoding = bech32_decode(addr)
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
    
    # Validazione per witness version 0 (bech32)
    if witver == 0:
        if encoding != "bech32":
            return None
        if len(spec) != 20 and len(spec) != 32:
            return None
    
    # Validazione per witness version 1+ (bech32m)
    if witver >= 1:
        if encoding != "bech32m":
            return None
        # Per Taproot (v1), deve essere 32 bytes
        if witver == 1 and len(spec) != 32:
            return None
    
    return bytes(spec)

def scripthash_from_spk(spk: bytes) -> str:
    """Calcola lo scripthash per Electrum/Fulcrum da scriptPubKey"""
    return hashlib.sha256(spk).digest()[::-1].hex()

# Funzioni per Schnorr signatures (BIP340) e Taproot (BIP341)
def tagged_hash(tag: str, data: bytes) -> bytes:
    """Calcola tagged hash secondo BIP340"""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()

def lift_x(x: int) -> tuple:
    """Lift x coordinate to point secondo BIP340"""
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    y_squared = (pow(x, 3, p) + 7) % p
    y = pow(y_squared, (p + 1) // 4, p)
    if pow(y, 2, p) != y_squared:
        return None
    return (x, y if y % 2 == 0 else p - y)

def schnorr_sign(private_key: bytes, message: bytes) -> bytes:
    """Firma Schnorr secondo BIP340"""
    from ecdsa.ellipticcurve import Point
    from ecdsa.util import number_to_string, string_to_number
    import secrets
    
    # Parametri della curva
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = SECP256k1.generator
    
    # Private key come intero
    d = string_to_number(private_key)
    if d == 0 or d >= n:
        raise ValueError("Invalid private key")
    
    # Public key point
    P = d * G
    px = P.x()
    py = P.y()
    
    # Se y è dispari, nega la private key (BIP340)
    if py % 2 != 0:
        d = n - d
    
    # Ricalcola P con la chiave corretta
    P = d * G
    px = P.x()
    
    # Nonce generation secondo BIP340
    aux_rand = secrets.token_bytes(32)  # 32 byte casuali
    t = (d ^ string_to_number(tagged_hash("BIP0340/aux", aux_rand))) % n
    k_bytes = tagged_hash("BIP0340/nonce", t.to_bytes(32, 'big') + px.to_bytes(32, 'big') + message)
    k = string_to_number(k_bytes) % n
    if k == 0:
        raise ValueError("Invalid nonce")
    
    # R = k*G
    R = k * G
    rx = R.x()
    ry = R.y()
    
    # Se ry è dispari, nega k (BIP340)
    if ry % 2 != 0:
        k = n - k
    
    # Challenge secondo BIP340
    e_bytes = tagged_hash("BIP0340/challenge", rx.to_bytes(32, 'big') + px.to_bytes(32, 'big') + message)
    e = string_to_number(e_bytes) % n
    
    # Signature s = k + e*d mod n
    s = (k + e * d) % n
    
    return rx.to_bytes(32, 'big') + s.to_bytes(32, 'big')

def schnorr_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifica firma Schnorr secondo BIP340"""
    from ecdsa.util import string_to_number
    
    if len(public_key) != 32 or len(signature) != 64:
        return False
    
    # Parametri
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = SECP256k1.generator
    
    # Parse signature
    r = string_to_number(signature[:32])
    s = string_to_number(signature[32:])
    
    if r >= p or s >= n:
        return False
    
    # Parse public key
    px = string_to_number(public_key)
    if px >= p:
        return False
    
    # Lift x coordinate
    point_data = lift_x(px)
    if point_data is None:
        return False
    
    px, py = point_data
    
    # Challenge
    e_bytes = tagged_hash("BIP0340/challenge", signature[:32] + public_key + message)
    e = string_to_number(e_bytes) % n
    
    # Verification: s*G = R + e*P
    try:
        from ecdsa.ellipticcurve import Point
        P = Point(SECP256k1.curve, px, py, n)
        R_expected = s * G + (-e % n) * P
        
        if R_expected.x() != r:
            return False
        if R_expected.y() % 2 != 0:
            return False
        
        return True
    except:
        return False

def taproot_tweak_private_key(private_key: bytes, merkle_root: bytes = None) -> bytes:
    """Applica tweak alla private key per Taproot"""
    from ecdsa.util import string_to_number, number_to_string
    
    # Se non c'è merkle root, usa solo key-path spending
    if merkle_root is None:
        merkle_root = b''
    
    # Calcola internal public key
    d = string_to_number(private_key)
    P = d * SECP256k1.generator
    px = P.x()
    py = P.y()
    
    # Se y è dispari, nega la private key
    if py % 2 != 0:
        d = (SECP256k1.order - d) % SECP256k1.order
    
    # Calcola tweak
    internal_pubkey = px.to_bytes(32, 'big')
    tweak_data = internal_pubkey + merkle_root
    tweak_hash = tagged_hash("TapTweak", tweak_data)
    tweak = string_to_number(tweak_hash)
    
    # Applica tweak
    tweaked_private_key = (d + tweak) % SECP256k1.order
    
    return number_to_string(tweaked_private_key, SECP256k1.order)

def taproot_tweak_public_key(internal_pubkey: bytes, merkle_root: bytes = None) -> bytes:
    """Applica tweak alla public key per Taproot"""
    from ecdsa.util import string_to_number
    from ecdsa.ellipticcurve import Point
    
    if len(internal_pubkey) != 32:
        raise ValueError("Internal pubkey deve essere 32 bytes")
    
    # Se non c'è merkle root, usa solo key-path spending
    if merkle_root is None:
        merkle_root = b''
    
    # Lift x coordinate
    px = string_to_number(internal_pubkey)
    point_data = lift_x(px)
    if point_data is None:
        raise ValueError("Invalid internal pubkey")
    
    px, py = point_data
    P = Point(SECP256k1.curve, px, py, SECP256k1.order)
    
    # Calcola tweak
    tweak_data = internal_pubkey + merkle_root
    tweak_hash = tagged_hash("TapTweak", tweak_data)
    tweak = string_to_number(tweak_hash)
    
    # Applica tweak: Q = P + tweak*G
    Q = P + tweak * SECP256k1.generator
    
    return Q.x().to_bytes(32, 'big')