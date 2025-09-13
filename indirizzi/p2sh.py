import secrets
import hashlib
import json
import ecdsa
import base58
from typing import Dict, List

NETWORK_CONFIG = {
    "mainnet": {"p2sh_prefix": b"\x05", "wif_prefix": b"\x80"},
    "testnet": {"p2sh_prefix": b"\xC4", "wif_prefix": b"\xEF"},
    "regtest": {"p2sh_prefix": b"\xC4", "wif_prefix": b"\xEF"},
}

def _to_wif(privkey: bytes, wif_prefix: bytes, compressed: bool = True) -> str:
    """Converte una chiave privata in WIF (aggiunge 0x01 se compressa)."""
    payload = wif_prefix + privkey + (b"\x01" if compressed else b"")
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def _gen_keypair(compressed: bool = True):
    """Genera (priv_hex, wif, pub_hex)."""
    sk_bytes = secrets.token_bytes(32)
    sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    raw = vk.to_string()  # 64 byte X||Y

    if compressed:
        x = raw[:32]
        y = raw[32:]
        prefix = b"\x02" if int.from_bytes(y, "big") % 2 == 0 else b"\x03"
        pub = prefix + x
    else:
        pub = b"\x04" + raw

    return sk_bytes.hex(), pub.hex(), pub

def _op_push(data: bytes) -> bytes:
    """pushdata minimale (lunghezze pubkey/redeem < 0x4c gestite direttamente)."""
    assert len(data) < 0x4c
    return bytes([len(data)]) + data

def _encode_multisig_redeem(m: int, pubkeys: List[bytes], n: int) -> bytes:
    """Costruisce redeemScript: OP_m <pub1> ... <pubN> OP_n OP_CHECKMULTISIG."""
    if not (1 <= m <= n <= 16):
        raise ValueError("Richiesto 1 <= m <= n <= 16")
    if any(len(pk) not in (33, 65) for pk in pubkeys):
        raise ValueError("Pubkey non valida (attese compresse 33B o non compresse 65B)")

    OP_CHECKMULTISIG = b"\xAE"
    OP_m = bytes([0x50 + m])  # OP_1 .. OP_16
    OP_n = bytes([0x50 + n])

    script = OP_m
    for pk in pubkeys:
        script += _op_push(pk)
    script += OP_n + OP_CHECKMULTISIG
    return script

def _hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def _script_pubkey_p2sh(script_hash160: bytes) -> bytes:
    # OP_HASH160 <20> <h160> OP_EQUAL
    return b"\xA9\x14" + script_hash160 + b"\x87"

def _address_p2sh(h160: bytes, ver: bytes) -> str:
    payload = ver + h160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def generate_p2sh_multisig(
    network: str = "mainnet",
    m: int = 2,
    n: int = 3,
    compressed: bool = True,
    sort_pubkeys: bool = True,  # BIP67: ordina le pubkey per evitare malleabilità del redeem
) -> Dict:
    """Genera JSON per un P2SH multisig m-of-n (con chiavi locali)."""
    cfg = NETWORK_CONFIG.get(network)
    if cfg is None:
        raise ValueError("Network non supportato (mainnet, testnet, regtest).")
    if not (1 <= m <= n <= 16):
        raise ValueError("Parametri m/n non validi (1 <= m <= n <= 16).")

    # genera n coppie chiave
    participants = []
    pubkeys_bytes = []
    for _ in range(n):
        priv_hex, pub_hex, pub_bytes = _gen_keypair(compressed)
        participants.append({
            "private_key_hex": priv_hex,
            "private_key_wif": _to_wif(bytes.fromhex(priv_hex), cfg["wif_prefix"], compressed),
            "public_key_hex": pub_hex,
        })
        pubkeys_bytes.append(pub_bytes)

    # BIP67: ordina le pubkey in modo deterministico (lexicografico sul byte array)
    if sort_pubkeys:
        pubkeys_bytes.sort()

    redeem = _encode_multisig_redeem(m, pubkeys_bytes, n)
    redeem_h160 = _hash160(redeem)
    spk = _script_pubkey_p2sh(redeem_h160)
    address = _address_p2sh(redeem_h160, cfg["p2sh_prefix"])

    result = {
        "network": network,
        "script_type": "p2sh-multisig",
        "m": m,
        "n": n,
        "redeem_script_hex": redeem.hex(),
        "participants": participants,
        "address": address
    }
    return result

def _redeem_asm(m: int, pubkeys: List[bytes], n: int) -> str:
    """Rappresentazione ASM comoda per debug."""
    def opnum(x): return f"OP_{x}"
    items = [opnum(m)] + [pk.hex() for pk in pubkeys] + [opnum(n), "OP_CHECKMULTISIG"]
    return " ".join(items)

def main():
    print("=== Generatore P2SH Multisig ===")
    net = input("Seleziona rete (mainnet/testnet/regtest): ").strip().lower()
    m = int(input("Quante firme richieste (m)? ").strip())
    n = int(input("Quante chiavi totali (n)? ").strip())
    comp_in = input("Pubkey compresse? (s/n): ").strip().lower()
    compressed = comp_in != "n"

    try:
        res = generate_p2sh_multisig(net, m, n, compressed, sort_pubkeys=True)
        print("\n--- Risultati ---")
        for k in ["network","script_type","m","n","redeem_script_hex"]:
            print(f"{k}: {res[k]}")
        print("\n-- Partecipanti --")
        for i, p in enumerate(res["participants"], 1):
            print(f"[{i}] pub: {p['public_key_hex']}")
            print(f"    priv: {p['private_key_hex']}")
            print(f"    wif: {p['private_key_wif']}")
        print(f"\naddress: {res['address']}")

        nome = input("\nNome file per salvare (senza estensione): ").strip() or "wallet_p2sh_multisig"
        if not nome.endswith(".json"): nome += ".json"
        with open(nome, "w") as f:
            json.dump(res, f, indent=4)
        print(f"Salvato in {nome}")
    except Exception as e:
        print("Errore:", e)

if __name__ == "__main__":
    main()
