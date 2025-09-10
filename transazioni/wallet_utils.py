import json
import sys
import glob
import base58
from typing import Tuple
from ecdsa import SigningKey, SECP256k1

from config import WALLET_JSON
from crypto_utils import decode_bech32_address

def select_wallet() -> str:
    """Cerca tutti i file wallet .json e permette all'utente di scegliere"""
    # Cerca tutti i file .json nella directory corrente
    wallet_files = glob.glob("*.json")
    
    if not wallet_files:
        print("❌ Nessun file wallet (.json) trovato nella directory corrente!")
        sys.exit(1)
    
    # Se c'è solo un wallet, lo usa automaticamente
    if len(wallet_files) == 1:
        print(f"📁 Trovato un solo wallet: {wallet_files[0]}")
        return wallet_files[0]
    
    # Mostra la lista dei wallet disponibili
    print("📁 Wallet disponibili:")
    for i, wallet_file in enumerate(wallet_files, 1):
        # Prova a leggere informazioni base dal wallet
        try:
            with open(wallet_file, 'r') as f:
                wallet_data = json.load(f)
            
            script_type = wallet_data.get('script_type', 'sconosciuto')
            network = wallet_data.get('network', 'sconosciuto')
            
            # Mostra indirizzo o chiave pubblica
            if 'address' in wallet_data:
                identifier = wallet_data['address'][:20] + "..."
            elif 'public_key_hex' in wallet_data:
                identifier = wallet_data['public_key_hex'][:20] + "..."
            else:
                identifier = "N/A"
            
            print(f"  {i}. {wallet_file} ({script_type.upper()}, {network}) - {identifier}")
        except Exception:
            print(f"  {i}. {wallet_file} (errore lettura)")
    
    # Chiede all'utente di scegliere
    while True:
        try:
            choice = input(f"\nSeleziona wallet (1-{len(wallet_files)}): ").strip()
            if not choice:
                continue
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(wallet_files):
                selected_wallet = wallet_files[choice_num - 1]
                print(f"✅ Wallet selezionato: {selected_wallet}")
                return selected_wallet
            else:
                print(f"❌ Inserisci un numero tra 1 e {len(wallet_files)}")
        except ValueError:
            print("❌ Inserisci un numero valido")
        except KeyboardInterrupt:
            print("\n👋 Operazione annullata")
            sys.exit(0)

class Wallet:
    """Classe per gestire un wallet Bitcoin"""
    
    def __init__(self, private_key: bytes, public_key: bytes, address: str, hash160: bytes):
        """Inizializza il wallet"""
        self.private_key = private_key
        self.public_key = public_key
        self.address = address
        self.hash160 = hash160
        self.signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    
    @property
    def is_bech32(self) -> bool:
        """Verifica se l'indirizzo è in formato bech32"""
        return self.address.startswith(("bc1", "tb1", "bcrt1"))
    
    @property
    def is_legacy(self) -> bool:
        """Verifica se l'indirizzo è in formato legacy (base58)"""
        return not self.is_bech32


def load_wallet(path: str = WALLET_JSON) -> Wallet:
    """Carica un wallet dal file JSON"""
    try:
        with open(path, "r") as f:
            wallet_data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"File wallet non trovato: {path}")
    
    # Estrae i dati dal JSON
    private_key = bytes.fromhex(wallet_data["private_key_hex"])
    public_key = bytes.fromhex(wallet_data["public_key_hex"])
    
    # Gestisce wallet P2PK che non hanno campo 'address'
    script_type = wallet_data.get("script_type", "p2pkh")
    
    if script_type == "p2pk":
        # Per P2PK usa la chiave pubblica hex come "indirizzo"
        address = wallet_data["public_key_hex"]
        hash160 = decode_address(address)  # decode_address già gestisce chiavi pubbliche hex
    else:
        # Per altri tipi usa il campo address
        address = wallet_data["address"].strip()
        hash160 = decode_address(address)
    
    if hash160 is None:
        raise ValueError(f"Indirizzo o chiave pubblica non valida: {address}")
    
    return Wallet(private_key, public_key, address, hash160)

def decode_address(address: str) -> bytes:
    """Decodifica un indirizzo Bitcoin e restituisce l'hash160 o chiave pubblica"""
    if address.startswith(("bc1", "tb1", "bcrt1")):
        # Indirizzo bech32
        return decode_bech32_address(address)
    elif is_public_key_hex(address):
        # Chiave pubblica hex per P2PK
        try:
            return bytes.fromhex(address)
        except ValueError:
            return None
    else:
        # Indirizzo legacy base58
        try:
            decoded = base58.b58decode_check(address)
            return decoded[1:]  # Rimuove il version byte
        except Exception:
            return None

def is_bech32_address(address: str) -> bool:
    """Verifica se un indirizzo è in formato bech32"""
    return address.startswith(("bc1", "tb1", "bcrt1"))

def is_legacy_address(address: str) -> bool:
    """Verifica se un indirizzo è in formato legacy
    
    Args:
        address: Indirizzo da verificare
        
    Returns:
        True se è legacy, False altrimenti
    """
    try:
        decoded = base58.b58decode_check(address)
        return len(decoded) == 21  # 1 byte version + 20 bytes hash
    except Exception:
        return False


def is_public_key_hex(address: str) -> bool:
    """Verifica se una stringa è una chiave pubblica valida in formato hex"""
    try:
        # Verifica che sia hex valido
        pubkey_bytes = bytes.fromhex(address)
        
        # Chiave pubblica compressa: 33 bytes che inizia con 02 o 03
        if len(pubkey_bytes) == 33 and pubkey_bytes[0] in (0x02, 0x03):
            return True
            
        # Chiave pubblica non compressa: 65 bytes che inizia con 04
        if len(pubkey_bytes) == 65 and pubkey_bytes[0] == 0x04:
            return True
            
        return False
    except ValueError:
        return False

def spk_p2pkh_from_h160(h160: bytes) -> bytes:
    """Crea scriptPubKey P2PKH da hash160"""
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"

def spk_p2wpkh_from_h160(h160: bytes) -> bytes:
    """Crea scriptPubKey P2WPKH da hash160"""
    return b"\x00\x14" + h160

def get_scriptpubkey_for_address(address: str, data: bytes) -> bytes:
    """Ottiene il scriptPubKey appropriato per un indirizzo o chiave pubblica"""
    if is_public_key_hex(address):
        # P2PK: usa la chiave pubblica direttamente
        from script_types import spk_p2pk
        return spk_p2pk(data)
    elif is_bech32_address(address):
        return spk_p2wpkh_from_h160(data)
    else:
        return spk_p2pkh_from_h160(data)

def validate_address(address: str) -> bool:
    """Valida un indirizzo Bitcoin o chiave pubblica P2PK"""
    return decode_address(address) is not None


def create_wallet_info(private_key_hex: str, public_key_hex: str, address: str) -> dict:
    """Crea un dizionario con le informazioni del wallet"""
    return {
        "private_key_hex": private_key_hex,
        "public_key_hex": public_key_hex,
        "address": address
    }

def save_wallet(wallet_info: dict, path: str = WALLET_JSON) -> None:
    """Salva le informazioni del wallet in un file JSON"""
    with open(path, "w") as f:
        json.dump(wallet_info, f, indent=2)