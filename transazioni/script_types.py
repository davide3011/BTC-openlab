from typing import Callable, Optional
from ecdsa import SigningKey

from crypto_utils import vi, der_low_s

def spk_p2pkh(pubkey_hash: bytes) -> bytes:
    """Crea scriptPubKey P2PKH"""
    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"

def spk_p2wpkh(pubkey_hash: bytes) -> bytes:
    """Crea scriptPubKey P2WPKH"""
    return b"\x00\x14" + pubkey_hash

def spk_p2pk(pubkey_bytes: bytes) -> bytes:
    """Crea scriptPubKey P2PK"""
    return bytes([len(pubkey_bytes)]) + pubkey_bytes + b"\xac"

def sig_p2pkh(z: bytes, sk: SigningKey, pub: bytes, spk_prev: bytes) -> bytes:
    """Crea scriptSig per input P2PKH"""
    # Firma il digest
    r, s = sk.sign_digest_deterministic(z, sigencode=lambda r, s, _: (r, s))
    sig = der_low_s(r, s) + b"\x01"  # SIGHASH_ALL
    
    # Costruisce scriptSig: <sig> <pubkey>
    return vi(len(sig)) + sig + vi(len(pub)) + pub

def sig_p2pk(z: bytes, sk: SigningKey, pub: bytes, spk_prev: bytes) -> bytes:
    """Crea scriptSig per input P2PK"""
    # Firma il digest
    r, s = sk.sign_digest_deterministic(z, sigencode=lambda r, s, _: (r, s))
    sig = der_low_s(r, s) + b"\x01"  # SIGHASH_ALL
    
    # Costruisce scriptSig: solo la firma
    return vi(len(sig)) + sig

class ScriptType:
    """Classe che definisce un tipo di script"""
    
    def __init__(self, name: str, build_func: Callable[[bytes], bytes], 
                 sign_func: Optional[Callable[[bytes, SigningKey, bytes, bytes], bytes]] = None):
        """Inizializza un tipo di script"""
        self.name = name
        self.build = build_func
        self.sign = sign_func
    
    def can_sign(self) -> bool:
        """Verifica se questo tipo può firmare input legacy"""
        return self.sign is not None
    
    def __str__(self) -> str:
        return self.name

SCRIPT_TYPES = {
    "p2pkh": ScriptType("P2PKH", spk_p2pkh, sig_p2pkh),
    "p2wpkh": ScriptType("P2WPKH", spk_p2wpkh, None),  # SegWit - firma gestita diversamente
    "p2pk": ScriptType("P2PK", spk_p2pk, sig_p2pk),
}

def get_script_type(name_or_spk) -> ScriptType:
    """Ottiene un tipo di script per nome o da scriptPubKey bytes"""
    if isinstance(name_or_spk, bytes):
        # Se sono bytes, determina il tipo dal scriptPubKey
        script_name = get_script_type_from_spk(name_or_spk)
        return SCRIPT_TYPES[script_name]
    elif isinstance(name_or_spk, str):
        # Se è una stringa, cerca direttamente
        if name_or_spk not in SCRIPT_TYPES:
            raise ValueError(f"Tipo di script non supportato: {name_or_spk}")
        return SCRIPT_TYPES[name_or_spk]
    else:
        raise ValueError(f"Tipo di argomento non supportato: {type(name_or_spk)}")

def get_script_type_by_name(name: str) -> ScriptType:
    """Ottiene un tipo di script per nome (funzione legacy)"""
    return get_script_type(name)

def is_witness_script(spk: bytes) -> bool:
    """Verifica se uno scriptPubKey è di tipo witness (SegWit)"""
    # P2WPKH: OP_0 + 20 bytes
    if len(spk) == 22 and spk[:2] == b"\x00\x14":
        return True
    
    # P2WSH: OP_0 + 32 bytes
    if len(spk) == 34 and spk[:2] == b"\x00\x20":
        return True
    
    return False

def get_script_type_from_spk(spk: bytes) -> str:
    """Determina il tipo di script da uno scriptPubKey"""
    # P2PKH: OP_DUP OP_HASH160 <20-bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac":
        return "p2pkh"
    
    # P2WPKH: OP_0 <20-bytes>
    if len(spk) == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh"
    
    # P2PK: <pubkey> OP_CHECKSIG
    if len(spk) >= 35 and spk[-1:] == b"\xac":
        pubkey_len = spk[0]
        if len(spk) == pubkey_len + 2:
            return "p2pk"
    
    raise ValueError(f"Tipo di script non riconosciuto: {spk.hex()}")

def create_scriptcode_p2wpkh(pubkey_hash: bytes) -> bytes:
    """Crea lo scriptCode per la firma P2WPKH (BIP143)"""
    return spk_p2pkh(pubkey_hash)