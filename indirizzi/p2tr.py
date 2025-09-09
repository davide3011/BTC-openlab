import secrets, hashlib, json, base58
from typing import Dict, Optional
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import Point

NETWORK_CONFIG = {
    'mainnet': {'hrp': 'bc',   'wif_prefix': b'\x80'},
    'testnet': {'hrp': 'tb',   'wif_prefix': b'\xEF'},
    'regtest': {'hrp': 'bcrt', 'wif_prefix': b'\xEF'},
}

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    """Calcola il polymod per bech32/bech32m"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xff
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    """Espande l'HRP per il calcolo bech32"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _bech32_create_checksum(hrp, data, spec="bech32m"):
    """Crea il checksum per bech32/bech32m"""
    const = 0x2bc830a3 if spec == "bech32m" else 1
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0,0,0,0,0,0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32m_encode(hrp: str, data: list) -> str:
    """Codifica dati in formato bech32m"""
    combined = data + _bech32_create_checksum(hrp, data, "bech32m")
    return hrp + "1" + "".join([_BECH32_CHARSET[d] for d in combined])

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[list]:
    """Converte bit tra diverse basi"""
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for b in data:
        if b < 0 or b >> frombits: return None
        acc = ((acc << frombits) | b) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv): return None
    return ret

def tagged_hash(tag: str, msg: bytes) -> bytes:
    """Calcola tagged hash BIP340"""
    tagh = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tagh + tagh + msg).digest()

curve = SECP256k1
G: Point = curve.generator
n = curve.order

def point_from_sk(sk_bytes: bytes) -> Point:
    """Genera punto pubblico da chiave privata"""
    sk = int.from_bytes(sk_bytes, 'big')
    if not (1 <= sk < n): raise ValueError("Chiave privata fuori range")
    return SigningKey.from_string(sk_bytes, curve=SECP256k1).verifying_key.pubkey.point

def xonly_bytes(P: Point) -> bytes:
    """Estrae coordinata x da punto (32 byte)"""
    return int(P.x()).to_bytes(32, 'big')

def pubkey_tweak(P: Point, merkle_root: Optional[bytes] = None):
    """Applica tweak Taproot al punto pubblico"""
    mr = b"" if merkle_root is None else merkle_root
    t = int.from_bytes(tagged_hash("TapTweak", xonly_bytes(P) + mr), 'big') % n
    if t == 0: raise ValueError("Tweak nullo, rigenera la chiave")
    return P + t*G, t

def to_wif(privkey: bytes, wif_prefix: bytes) -> str:
    """Converte chiave privata in formato WIF"""
    extended = wif_prefix + privkey + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return base58.b58encode(extended + checksum).decode()

def generate_p2tr_address(network: str = 'mainnet') -> Dict[str, str]:
    """Genera indirizzo P2TR completo"""
    cfg = NETWORK_CONFIG.get(network)
    if not cfg: raise ValueError("Network non supportato (mainnet, testnet, regtest).")
    
    sk = secrets.token_bytes(32)
    P = point_from_sk(sk)
    Q, t = pubkey_tweak(P, merkle_root=None)
    prog = xonly_bytes(Q)
    data = [1] + convertbits(prog, 8, 5, True)
    address = bech32m_encode(cfg['hrp'], data)
    wif = to_wif(sk, cfg['wif_prefix'])
    
    return {
        "network": network,
        "script_type": "p2tr",
        "private_key_hex": sk.hex(),
        "private_key_wif": wif,
        "internal_pubkey_x_hex": xonly_bytes(P).hex(),
        "address": address
    }

def main():
    """Funzione principale interattiva"""
    net = input("Seleziona rete (mainnet/testnet/regtest): ").strip().lower()
    try:
        res = generate_p2tr_address(net)
        print("\n--- Risultati P2TR ---")
        for k, v in res.items(): print(f"{k}: {v}")
        nome = input("\nNome file per salvare (senza estensione): ").strip() or "wallet_p2tr"
        if not nome.endswith(".json"): nome += ".json"
        with open(nome, "w") as f: json.dump(res, f, indent=4)
        print(f"Salvato in {nome}")
    except Exception as e: print("Errore:", e)

if __name__ == "__main__":
    main()
