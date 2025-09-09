# ============================================================================
# GENERATORE DI INDIRIZZI BITCOIN SEGWIT (P2WPKH)
# ============================================================================
# Questo script genera indirizzi Bitcoin SegWit (P2WPKH) per diverse reti
# (mainnet, testnet, regtest) e salva i dati in un file JSON.
#
# Un indirizzo P2WPKH (Pay-to-Witness-Public-Key-Hash) è un tipo di indirizzo
# Bitcoin che utilizza la tecnologia SegWit (Segregated Witness), introdotta
# per migliorare la scalabilità e ridurre le commissioni di transazione.

# Importazione delle librerie necessarie
import secrets      # Per generare numeri casuali crittograficamente sicuri
import hashlib      # Per le funzioni di hashing (SHA256, RIPEMD160)
import json         # Per salvare i dati in formato JSON
import ecdsa        # Per la crittografia a curva ellittica (ECDSA)
import base58       # Per la codifica Base58 (usata nel formato WIF)
from bech32 import bech32_encode, convertbits  # Per la codifica Bech32 (usata negli indirizzi SegWit)
from typing import Dict  # Per i suggerimenti di tipo

# Configurazione per ogni rete Bitcoin
# - hrp (Human Readable Part): prefisso leggibile dell'indirizzo Bech32
# - wif_prefix: prefisso per il formato WIF (Wallet Import Format) della chiave privata
NETWORK_CONFIG = {
    'mainnet': {'hrp': 'bc',   'wif_prefix': b'\x80'},  # Rete principale di Bitcoin
    'testnet': {'hrp': 'tb',   'wif_prefix': b'\xEF'},  # Rete di test di Bitcoin
    'regtest': {'hrp': 'bcrt', 'wif_prefix': b'\xEF'},  # Rete di regressione (per sviluppo locale)
}

def generate_segwit_address(network: str = 'mainnet', compressed: bool = True) -> Dict[str, str]:
    """Genera una chiave privata, una chiave pubblica (compressa o non compressa),
    il relativo WIF e l'indirizzo segwit bech32 per il network specificato.
    
    Args:
        network: Il network da utilizzare ('mainnet', 'testnet', 'regtest')
        compressed: Se True, utilizza chiavi pubbliche compresse, altrimenti non compresse
    
    Returns:
        Un dizionario contenente la chiave privata (hex e WIF), la chiave pubblica (hex),
        l'indirizzo SegWit e il network utilizzato
    """
    # Ottiene la configurazione per la rete specificata
    config = NETWORK_CONFIG.get(network)
    if config is None:
        raise ValueError("Network non supportato. Scegli tra 'mainnet', 'testnet' o 'regtest'.")

    # 1. Genera la chiave privata (32 byte = 256 bit)
    # Una chiave privata Bitcoin è semplicemente un numero casuale di 256 bit
    private_key = secrets.token_bytes(32)  # Genera 32 byte casuali (256 bit)
    private_key_hex = private_key.hex()    # Converte in formato esadecimale

    # 2. Deriva la chiave pubblica dalla chiave privata usando la curva ellittica SECP256k1
    # La curva SECP256k1 è la curva ellittica standard usata da Bitcoin
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()  # Ottiene la chiave di verifica (chiave pubblica)
    pubkey_bytes = vk.to_string()  # 64 byte: [32 byte coordinata X | 32 byte coordinata Y]
    
    # Le chiavi pubbliche possono essere in formato compresso o non compresso
    if compressed:
        # Formato compresso: prefisso (02 o 03) + coordinata X
        # Il prefisso indica la parità della coordinata Y (02 = pari, 03 = dispari)
        # Questo permette di ricostruire la coordinata Y quando necessario
        x = pubkey_bytes[:32]  # Primi 32 byte (coordinata X)
        y = pubkey_bytes[32:]  # Ultimi 32 byte (coordinata Y)
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'  # Determina la parità di Y
        pubkey = prefix + x  # Chiave pubblica compressa (33 byte)
    else:
        # Formato non compresso: prefisso (04) + coordinata X + coordinata Y
        pubkey = b'\x04' + pubkey_bytes  # Chiave pubblica non compressa (65 byte)
    
    pubkey_hex = pubkey.hex()  # Converte in formato esadecimale

    # 3. Calcola HASH160 della chiave pubblica (SHA256 -> RIPEMD160)
    # Questo è lo standard Bitcoin per ottenere un hash più corto della chiave pubblica
    sha256_pubkey = hashlib.sha256(pubkey).digest()  # Prima hash con SHA256
    ripemd160 = hashlib.new('ripemd160', sha256_pubkey).digest()  # Poi hash con RIPEMD160

    # 4. Crea il witness program e codifica in Bech32 (P2WPKH)
    # Per P2WPKH, il witness program è: [versione (0)] + [hash della chiave pubblica]
    # Converti l'hash (20 byte) in gruppi da 5 bit per la codifica Bech32
    converted = convertbits(list(ripemd160), 8, 5)  # Converte da base 8 (byte) a base 5 (per Bech32)
    if converted is None:
        raise ValueError("Errore nella conversione dei bit per la codifica Bech32")
    data = [0] + converted  # Aggiunge il byte della witness version (0 per P2WPKH)
    address = bech32_encode(config['hrp'], data)  # Codifica in formato Bech32

    # 5. Crea la rappresentazione WIF della chiave privata
    # WIF (Wallet Import Format) è un formato standard per rappresentare le chiavi private
    if compressed:
        # Aggiunge il byte che indica che la chiave è compressa (0x01)
        extended_key = config['wif_prefix'] + private_key + b'\x01'
    else:
        # Senza il byte di compressione per chiavi non compresse
        extended_key = config['wif_prefix'] + private_key
    
    # Calcola il checksum (primi 4 byte del doppio hash SHA256)
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    private_key_wif = base58.b58encode(extended_key + checksum).decode()  # Codifica in Base58

    # Restituisce un dizionario con tutte le informazioni generate
    return {
        'network': network,                  # Rete utilizzata
        'script_type': 'p2wpkh',            # Script type identifier
        'private_key_hex': private_key_hex,  # Chiave privata in formato esadecimale
        'private_key_wif': private_key_wif,  # Chiave privata in formato WIF
        'public_key_hex': pubkey_hex,        # Chiave pubblica in formato esadecimale
        'address': address                   # Indirizzo SegWit in formato Bech32
    }

def main():
    """Funzione principale che gestisce l'interazione con l'utente e il salvataggio dei dati."""
    # Richiede all'utente di selezionare la rete
    network = input("Seleziona il tipo di rete (mainnet, testnet, regtest): ").strip().lower()
    
    # Richiede all'utente se utilizzare chiavi compresse
    compressed_input = input("Utilizzare chiavi compresse? (s/n): ").strip().lower()
    compressed = compressed_input != 'n'  # Default: chiavi compresse (qualsiasi input diverso da 'n')
    
    try:
        # Genera l'indirizzo SegWit e le relative chiavi
        result = generate_segwit_address(network, compressed)
        
        # Mostra i risultati all'utente
        print("\n--- Risultati ---")
        print(f"Network: {result['network']}")
        print("Chiave privata (hex):", result['private_key_hex'])
        print("Chiave privata (WIF):", result['private_key_wif'])
        key_type = "compressa" if compressed else "non compressa"
        print(f"Chiave pubblica ({key_type}, hex):", result['public_key_hex'])
        print("Indirizzo segwit bech32:", result['address'])
        
        # Salva i risultati in un file JSON
        nome_file = input("\nInserisci il nome del file (senza estensione) per salvare i dati: ").strip()
        if not nome_file:
            nome_file = "wallet"  # Nome di default
            print("Nome del file non valido. Verrà utilizzato il nome di default: wallet.json")
        if not nome_file.endswith('.json'):
            nome_file += '.json'  # Aggiunge l'estensione .json se non presente
        
        # Scrive i dati nel file JSON con indentazione per leggibilità
        with open(nome_file, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"Dati salvati correttamente nel file: {nome_file}")
    
    except Exception as e:
        # Gestione degli errori
        print("Errore:", e)

# Punto di ingresso dello script quando eseguito direttamente
if __name__ == '__main__':
    main()
