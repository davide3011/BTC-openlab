import secrets
import hashlib
import json
import ecdsa
import base58
from typing import Dict

NETWORK_CONFIG = {
    'mainnet': {'addr_prefix': b'\x00', 'wif_prefix': b'\x80'},
    'testnet': {'addr_prefix': b'\x6f', 'wif_prefix': b'\xEF'},
    'regtest': {'addr_prefix': b'\x6f', 'wif_prefix': b'\xEF'},
}

def generate_legacy_address(network: str = 'mainnet', compressed: bool = True) -> Dict[str, str]:
    """Genera chiave privata, pubblica, WIF e indirizzo Bitcoin Legacy (P2PKH)."""
    config = NETWORK_CONFIG.get(network)
    if config is None:
        raise ValueError("Network non supportato. Scegli tra 'mainnet', 'testnet' o 'regtest'.")

    private_key = secrets.token_bytes(32)
    private_key_hex = private_key.hex()

    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    pubkey_bytes = vk.to_string()
    
    if compressed:
        x = pubkey_bytes[:32]
        y = pubkey_bytes[32:]
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'
        pubkey = prefix + x
    else:
        pubkey = b'\x04' + pubkey_bytes
    
    pubkey_hex = pubkey.hex()

    sha256_pubkey = hashlib.sha256(pubkey).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_pubkey).digest()
    
    addr_payload = config['addr_prefix'] + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(addr_payload).digest()).digest()[:4]
    address = base58.b58encode(addr_payload + checksum).decode()

    if compressed:
        extended_key = config['wif_prefix'] + private_key + b'\x01'
    else:
        extended_key = config['wif_prefix'] + private_key
    
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    private_key_wif = base58.b58encode(extended_key + checksum).decode()

    return {
        'network': network,
        'script_type': 'p2pkh',
        'private_key_hex': private_key_hex,
        'private_key_wif': private_key_wif,
        'public_key_hex': pubkey_hex,
        'address': address
    }



def main():
    """Funzione principale che gestisce l'interazione con l'utente e il salvataggio dei dati."""
    network = input("Seleziona il tipo di rete (mainnet, testnet, regtest): ").strip().lower()
    compressed_input = input("Utilizzare chiavi compresse? (s/n): ").strip().lower()
    compressed = compressed_input != 'n'
    
    try:
        result = generate_legacy_address(network, compressed)
        
        print("\n--- Risultati ---")
        print(f"Network: {result['network']}")
        print(f"Script type: {result['script_type']}")
        print("Chiave privata (hex):", result['private_key_hex'])
        print("Chiave privata (WIF):", result['private_key_wif'])
        key_type = "compressa" if compressed else "non compressa"
        print(f"Chiave pubblica ({key_type}, hex):", result['public_key_hex'])
        print("Indirizzo:", result['address'])
        
        nome_file = input("\nInserisci il nome del file (senza estensione) per salvare i dati: ").strip()
        if not nome_file:
            nome_file = "wallet"
            print("Nome del file non valido. Verrà utilizzato il nome di default: wallet.json")
        if not nome_file.endswith('.json'):
            nome_file += '.json'
        
        with open(nome_file, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"Dati salvati correttamente nel file: {nome_file}")
    
    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
