from typing import Callable, Optional, List
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

def spk_p2sh(script_hash: bytes) -> bytes:
    """Crea scriptPubKey P2SH"""
    return b"\xa9\x14" + script_hash + b"\x87"

def spk_p2tr(output_pubkey: bytes) -> bytes:
    """Crea scriptPubKey P2TR (Taproot)"""
    if len(output_pubkey) != 32:
        raise ValueError("Output pubkey deve essere 32 bytes")
    return b"\x51\x20" + output_pubkey  # OP_1 + 32 bytes

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

def parse_multisig_redeem_script(redeem_script: bytes) -> List[bytes]:
    """Parsa un redeem script multisig per estrarre le chiavi pubbliche nell'ordine corretto"""
    if len(redeem_script) < 4:
        raise ValueError("Redeem script troppo corto")
    
    # Verifica che inizi con OP_M (0x51 = OP_1, 0x52 = OP_2, etc.)
    if redeem_script[0] < 0x51 or redeem_script[0] > 0x60:
        raise ValueError("Redeem script non valido: deve iniziare con OP_M")
    
    pubkeys = []
    pos = 1  # Salta OP_M iniziale
    
    while pos < len(redeem_script) - 2:  # -2 per OP_N e OP_CHECKMULTISIG finali
        # Legge la lunghezza della chiave pubblica
        if pos >= len(redeem_script):
            break
        
        pubkey_len = redeem_script[pos]
        pos += 1
        
        # Verifica che la lunghezza sia valida per una chiave pubblica
        if pubkey_len not in [33, 65]:  # Compressed o uncompressed
            # Se non è una lunghezza di chiave pubblica valida, potrebbe essere OP_N
            break
        
        # Estrae la chiave pubblica
        if pos + pubkey_len > len(redeem_script):
            break
        
        pubkey = redeem_script[pos:pos + pubkey_len]
        pubkeys.append(pubkey)
        pos += pubkey_len
    
    return pubkeys

def sig_p2sh_multisig(z: bytes, signing_keys: List[SigningKey], redeem_script: bytes, m: int) -> bytes:
    """Crea scriptSig per input P2SH multisig"""
    # Parsa il redeem script per ottenere l'ordine corretto delle chiavi pubbliche
    pubkeys_in_script = parse_multisig_redeem_script(redeem_script)
    
    # Crea un mapping dalle chiavi pubbliche alle chiavi private
    pubkey_to_privkey = {}
    for sk in signing_keys:
        # Ottiene la chiave pubblica compressa dalla chiave privata
        vk = sk.verifying_key
        pubkey_compressed = b"\x02" if vk.pubkey.point.y() % 2 == 0 else b"\x03"
        pubkey_compressed += vk.pubkey.point.x().to_bytes(32, 'big')
        pubkey_to_privkey[pubkey_compressed] = sk
        
        # Prova anche la versione non compressa
        pubkey_uncompressed = b"\x04" + vk.pubkey.point.x().to_bytes(32, 'big') + vk.pubkey.point.y().to_bytes(32, 'big')
        pubkey_to_privkey[pubkey_uncompressed] = sk
    
    # Crea le firme nell'ordine corretto delle chiavi pubbliche nel redeem script
    signatures = []
    signatures_created = 0
    
    for pubkey in pubkeys_in_script:
        if signatures_created >= m:
            break
        
        if pubkey in pubkey_to_privkey:
            sk = pubkey_to_privkey[pubkey]
            r, s = sk.sign_digest_deterministic(z, sigencode=lambda r, s, _: (r, s))
            sig = der_low_s(r, s) + b"\x01"  # SIGHASH_ALL
            signatures.append(sig)
            signatures_created += 1
    
    if signatures_created < m:
        raise ValueError(f"Impossibile creare {m} firme: solo {signatures_created} chiavi disponibili")
    
    # Funzione helper per push corretto
    def push_data(data: bytes) -> bytes:
        if len(data) <= 75:
            return bytes([len(data)]) + data
        elif len(data) <= 255:
            return b"\x4c" + bytes([len(data)]) + data  # OP_PUSHDATA1
        else:
            raise ValueError("Data troppo lunga per push")
    
    # Costruisce scriptSig: OP_0 <sig1> <sig2> ... <redeemScript>
    script_sig_parts = []
    script_sig_parts.append(b"\x00")  # OP_0 (dummy element per bug multisig)
    
    # Aggiunge le firme
    for sig in signatures:
        script_sig_parts.append(push_data(sig))
    
    # Aggiunge il redeem script
    script_sig_parts.append(push_data(redeem_script))
    
    return b"".join(script_sig_parts)

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
    "p2sh": ScriptType("P2SH", spk_p2sh, None),  # P2SH - firma gestita con funzione speciale
    "p2tr": ScriptType("P2TR", spk_p2tr, None),  # Taproot - firma gestita con Schnorr
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
    """Verifica se uno scriptPubKey è di tipo witness (SegWit o Taproot)"""
    # P2WPKH: OP_0 + 20 bytes
    if len(spk) == 22 and spk[:2] == b"\x00\x14":
        return True
    
    # P2WSH: OP_0 + 32 bytes
    if len(spk) == 34 and spk[:2] == b"\x00\x20":
        return True
    
    # P2TR: OP_1 + 32 bytes
    if len(spk) == 34 and spk[:2] == b"\x51\x20":
        return True
    
    return False

def get_script_type_from_spk(spk: bytes) -> str:
    """Determina il tipo di script da uno scriptPubKey"""
    # P2PKH: OP_DUP OP_HASH160 <20-bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac":
        return "p2pkh"
    
    # P2SH: OP_HASH160 <20-bytes> OP_EQUAL
    if len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[-1:] == b"\x87":
        return "p2sh"
    
    # P2WPKH: OP_0 <20-bytes>
    if len(spk) == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh"
    
    # P2TR: OP_1 <32-bytes>
    if len(spk) == 34 and spk[:2] == b"\x51\x20":
        return "p2tr"
    
    # P2PK: <pubkey> OP_CHECKSIG
    if len(spk) >= 35 and spk[-1:] == b"\xac":
        pubkey_len = spk[0]
        if len(spk) == pubkey_len + 2:
            return "p2pk"
    
    raise ValueError(f"Tipo di script non riconosciuto: {spk.hex()}")

def create_scriptcode_p2wpkh(pubkey_hash: bytes) -> bytes:
    """Crea lo scriptCode per la firma P2WPKH (BIP143)"""
    return spk_p2pkh(pubkey_hash)