# GENERATORE DI INDIRIZZI BITCOIN LEGACY (P2PKH)
# Genera indirizzi Bitcoin Legacy per diverse reti e salva i dati in JSON

import secrets  # Per generare numeri casuali crittograficamente sicuri
import hashlib  # Per le funzioni di hashing (SHA256, RIPEMD160)
import json     # Per salvare i dati in formato JSON
import ecdsa    # Per le operazioni con curve ellittiche
import base58   # Per la codifica Base58Check
import os       # Per operazioni sul filesystem
from typing import Dict, Tuple, Optional  # Per i type hints
from functools import lru_cache  # Per la memorizzazione dei risultati delle funzioni

# Configurazione reti Bitcoin
# Ogni rete ha prefissi diversi per gli indirizzi e il formato WIF
NETWORK_CONFIG = {
    'mainnet': {'addr_prefix': b'\x00', 'wif_prefix': b'\x80'},  # Rete principale
    'testnet': {'addr_prefix': b'\x6f', 'wif_prefix': b'\xEF'},  # Rete di test
    'regtest': {'addr_prefix': b'\x6f', 'wif_prefix': b'\xEF'},  # Rete di regressione (stessi prefissi del testnet)
}

# Funzioni helper ottimizzate
def double_sha256(data: bytes) -> bytes:
    """Calcola il doppio hash SHA256 (SHA256(SHA256(data)))
    
    Questo è un metodo standard usato in Bitcoin per calcolare checksum
    e per altre operazioni di hashing.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash160(data: bytes) -> bytes:
    """Calcola l'hash HASH160 (RIPEMD160(SHA256(data)))
    
    Questo metodo è usato in Bitcoin per generare indirizzi a partire
    dalle chiavi pubbliche, riducendo la dimensione e aumentando la sicurezza.
    """
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def encode_base58check(payload: bytes) -> str:
    """Codifica un payload in formato Base58Check
    
    Base58Check è un formato di codifica usato in Bitcoin che:
    1. Converte i dati binari in caratteri leggibili
    2. Esclude caratteri ambigui (0, O, I, l)
    3. Aggiunge un checksum per rilevare errori di trascrizione
    
    Args:
        payload: I dati binari da codificare
        
    Returns:
        La stringa codificata in Base58Check
    """
    return base58.b58encode(payload + double_sha256(payload)[:4]).decode()

def create_public_key(private_key: bytes, compressed: bool = True) -> Tuple[bytes, str]:
    """Crea una chiave pubblica a partire da una chiave privata
    
    In Bitcoin, le chiavi pubbliche sono punti sulla curva ellittica secp256k1.
    Possono essere rappresentate in formato compresso (33 byte) o non compresso (65 byte).
    
    Args:
        private_key: La chiave privata in formato bytes
        compressed: Se True, genera una chiave pubblica compressa
        
    Returns:
        Una tupla contenente (chiave_pubblica_bytes, chiave_pubblica_hex)
    """
    # Crea un oggetto SigningKey dalla libreria ecdsa usando la chiave privata
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    # Ottiene la chiave di verifica (chiave pubblica)
    vk = sk.get_verifying_key()
    # Converte la chiave pubblica in bytes (coordinate x e y del punto sulla curva)
    pubkey_bytes = vk.to_string()
    
    # Compressione della chiave pubblica se richiesto
    if compressed:
        # Estrae le coordinate x e y (32 byte ciascuna)
        x, y = pubkey_bytes[:32], pubkey_bytes[32:]
        # Il prefisso dipende dalla parità di y: 02 se pari, 03 se dispari
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'
        # La chiave compressa contiene solo il prefisso e la coordinata x
        pubkey = prefix + x
    else:
        # La chiave non compressa ha il prefisso 04 seguito dalle coordinate x e y
        pubkey = b'\x04' + pubkey_bytes

    return pubkey, pubkey.hex()

@lru_cache(maxsize=32)
def get_network_config(network: str) -> Dict:
    """Ottiene la configurazione di rete con cache per migliorare le prestazioni
    
    Verifica che la rete richiesta sia supportata e restituisce i suoi parametri.
    Usa @lru_cache per memorizzare i risultati e evitare calcoli ripetuti.
    
    Args:
        network: Il nome della rete (mainnet, testnet, regtest)
        
    Returns:
        Un dizionario con i parametri di configurazione della rete
        
    Raises:
        ValueError: Se la rete specificata non è supportata
    """
    if network not in NETWORK_CONFIG:
        valid_networks = ", ".join(list(NETWORK_CONFIG.keys())[:-1]) + f" o {list(NETWORK_CONFIG.keys())[-1]}"
        raise ValueError(f"Network '{network}' non supportato. Scegli tra {valid_networks}.")
    return NETWORK_CONFIG[network]

def generate_legacy_address(network: str = 'mainnet', compressed: bool = True) -> Dict[str, str]:
    """Genera chiave privata, pubblica, WIF e indirizzo Bitcoin Legacy (P2PKH)
    
    Questo è il processo completo di generazione di un indirizzo Bitcoin:
    1. Genera una chiave privata casuale
    2. Deriva la chiave pubblica corrispondente
    3. Calcola l'hash della chiave pubblica
    4. Crea l'indirizzo aggiungendo il prefisso di rete e codificando in Base58Check
    5. Codifica la chiave privata in formato WIF
    
    Args:
        network: La rete Bitcoin da utilizzare (mainnet, testnet, regtest)
        compressed: Se True, usa chiavi pubbliche compresse
        
    Returns:
        Un dizionario contenente chiave privata, WIF, chiave pubblica e indirizzo
    """
    # Ottiene i parametri di configurazione per la rete specificata
    config = get_network_config(network)
    
    # Generazione chiavi
    # Crea una chiave privata casuale di 32 byte (256 bit)
    private_key = secrets.token_bytes(32)
    private_key_hex = private_key.hex()
    # Deriva la chiave pubblica dalla chiave privata
    pubkey, pubkey_hex = create_public_key(private_key, compressed)
    
    # Creazione indirizzo e WIF
    # Calcola l'hash della chiave pubblica
    pubkey_hash = hash160(pubkey)
    # Crea il payload dell'indirizzo aggiungendo il prefisso di rete
    addr_payload = config['addr_prefix'] + pubkey_hash
    # Crea il payload WIF aggiungendo il prefisso di rete e il suffisso di compressione se necessario
    wif_payload = config['wif_prefix'] + private_key + (b'\x01' if compressed else b'')
    
    # Restituisce tutte le informazioni in un dizionario
    return {
        'network': network,                                 # Rete utilizzata
        'script_type': 'p2pkh',                             # Type of Bitcoin script
        'private_key_hex': private_key_hex,                 # Chiave privata in formato esadecimale
        'private_key_wif': encode_base58check(wif_payload), # Chiave privata in formato WIF
        'public_key_hex': pubkey_hex,                       # Chiave pubblica in formato esadecimale
        'address': encode_base58check(addr_payload)         # Indirizzo Bitcoin
    }

# Funzioni per l'interazione con l'utente
def get_valid_network() -> str:
    """Richiede all'utente di selezionare una rete Bitcoin valida
    
    Mostra le opzioni disponibili e verifica che l'input sia valido.
    
    Returns:
        Il nome della rete selezionata
    """
    valid_networks = list(NETWORK_CONFIG.keys())
    network_str = ", ".join(valid_networks[:-1]) + f" o {valid_networks[-1]}"
    
    while True:
        network = input(f"Seleziona il tipo di rete ({network_str}): ").strip().lower()
        if network in NETWORK_CONFIG:
            return network
        print(f"Rete non valida. Scegli tra {network_str}.")

def get_valid_filename(default_name: str = "wallet") -> str:
    """Richiede all'utente di inserire un nome di file valido
    
    Verifica e sanitizza l'input dell'utente, usando un valore predefinito se necessario.
    
    Args:
        default_name: Il nome di file predefinito da usare se l'input non è valido
        
    Returns:
        Un nome di file valido con estensione .json
    """
    nome_file = input("\nInserisci il nome del file (senza estensione) per salvare i dati: ").strip()
    
    # Rimuovi caratteri non validi e imposta default se necessario
    nome_file = ''.join(c for c in nome_file if c.isalnum() or c in "_-")
    if not nome_file:
        nome_file = default_name
        print(f"Nome del file non valido. Verrà utilizzato il nome di default: {default_name}.json")
    
    # Assicura estensione .json
    return nome_file if nome_file.endswith('.json') else nome_file + '.json'

def save_to_json(data: Dict, filename: str) -> None:
    """Salva i dati in un file JSON
    
    Crea la directory se necessario e salva i dati in formato JSON leggibile.
    
    Args:
        data: I dati da salvare
        filename: Il nome del file in cui salvare i dati
    """
    # Crea la directory se non esiste
    directory = os.path.dirname(filename)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        
    # Scrive i dati nel file JSON con indentazione per leggibilità
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Dati salvati correttamente nel file: {filename}")

def main():
    """Funzione principale per gestire l'interazione con l'utente e il salvataggio dei dati
    
    Coordina l'intero processo di generazione dell'indirizzo e gestisce le eccezioni.
    """
    try:
        # Ottieni parametri e genera indirizzo
        network = get_valid_network()  # Chiede all'utente di selezionare una rete
        compressed = input("Utilizzare chiavi compresse? (s/n): ").strip().lower() != 'n'  # Default: sì
        # Genera l'indirizzo e le chiavi
        result = generate_legacy_address(network, compressed)
        
        # Mostra risultati
        print("\n--- Risultati ---")
        print(f"Network: {result['network']}")
        print("Chiave privata (hex):", result['private_key_hex'])       # Chiave privata in esadecimale
        print("Chiave privata (WIF):", result['private_key_wif'])       # Chiave privata in formato WIF
        print(f"Chiave pubblica ({('compressa' if compressed else 'non compressa')}, hex):", result['public_key_hex'])
        print("Indirizzo Legacy P2PKH:", result['address'])             # L'indirizzo Bitcoin generato
        
        # Salva dati in JSON
        save_to_json(result, get_valid_filename())  # Salva tutti i dati in un file JSON
    
    except ValueError as e:
        # Gestisce errori di validazione (es. rete non valida)
        print(f"Errore di validazione: {e}")
    except PermissionError:
        # Gestisce errori di permesso nella scrittura del file
        print("Errore: Permesso negato per la scrittura del file. Prova con un percorso diverso.")
    except Exception as e:
        # Gestisce altri errori imprevisti
        print(f"Errore imprevisto: {e}")

# Punto di ingresso
if __name__ == '__main__':
    main()  # Esegue la funzione principale quando lo script viene eseguito direttamente
