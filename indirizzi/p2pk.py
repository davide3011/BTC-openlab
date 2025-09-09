import secrets
import hashlib
import json
import ecdsa
import base58
from typing import Dict

NETWORK_CONFIG = {
    'mainnet': {'wif_prefix': b'\x80'},
    'testnet': {'wif_prefix': b'\xEF'},
    'regtest': {'wif_prefix': b'\xEF'},
}

def generate_p2pk(network: str = 'mainnet', compressed: bool = False) -> Dict[str, str]:
    """
    Genera chiave privata, chiave pubblica e WIF per P2PK.

    Args:
        network: 'mainnet', 'testnet' o 'regtest'
        compressed: True per chiave pubblica compressa (33 byte), False per non compressa (65 byte)

    Returns:
        Dizionario con network, script_type, private_key_hex, private_key_wif, public_key_hex
    """
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
        public_key = prefix + x
    else:
        public_key = b'\x04' + pubkey_bytes

    public_key_hex = public_key.hex()

    if compressed:
        extended_key = config['wif_prefix'] + private_key + b'\x01'
    else:
        extended_key = config['wif_prefix'] + private_key

    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode()

    return {
        'network': network,
        'script_type': 'p2pk',
        'private_key_hex': private_key_hex,
        'private_key_wif': wif,
        'public_key_hex': public_key_hex
    }

def main():
    """Genera e salva dati P2PK."""
    network = input("Seleziona il tipo di rete (mainnet, testnet, regtest): ").strip().lower()
    compressed_input = input("Utilizzare chiavi compresse (s/n): ").strip().lower()
    while compressed_input not in ['s', 'n']:
        print("Inserisci 's' per si o 'n' per no.")
        compressed_input = input("Utilizzare chiavi compresse (s/n): ").strip().lower()
    compressed = (compressed_input == 's')

    try:
        result = generate_p2pk(network, compressed)
        
        print("\n--- Risultati ---")
        print("Network:", result['network'])
        print("Script type:", result['script_type'])
        print("Chiave privata (hex):", result['private_key_hex'])
        print("Chiave privata (WIF):", result['private_key_wif'])
        key_type = "compressa" if compressed else "non compressa"
        print(f"Chiave pubblica ({key_type}, hex):", result['public_key_hex'])
        
        nome_file = input("\nInserisci il nome del file (senza estensione) per salvare i dati: ").strip()
        if not nome_file:
            nome_file = "dati_p2pk"
            print("Nome del file non valido. Verrà utilizzato il nome di default: dati_p2pk.json")
        if not nome_file.endswith('.json'):
            nome_file += '.json'
        
        with open(nome_file, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"Dati salvati correttamente nel file: {nome_file}")

    except Exception as e:
        print("Errore:", e)

if __name__ == '__main__':
    main()
