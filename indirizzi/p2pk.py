import secrets       # Per generare numeri casuali crittograficamente sicuri
import hashlib       # Per le funzioni di hashing (SHA256)
import json          # Per salvare i dati in formato JSON
import ecdsa         # Per la crittografia a curva ellittica (ECDSA)
import base58        # Per la codifica Base58 (usata nel formato WIF)
from typing import Dict

# Configurazione per il WIF in base al network:
# - mainnet usa il prefisso 0x80 (rete principale di Bitcoin)
# - testnet e regtest usano il prefisso 0xEF (reti di test)
# Questi prefissi sono standard nel protocollo Bitcoin e servono a distinguere
# le chiavi private delle diverse reti.
NETWORK_CONFIG = {
    'mainnet': {'wif_prefix': b'\x80'},  # Prefisso per la rete principale
    'testnet': {'wif_prefix': b'\xEF'},  # Prefisso per la rete di test
    'regtest': {'wif_prefix': b'\xEF'},  # Prefisso per la rete di regression test
}

def generate_p2pk(network: str = 'mainnet', compressed: bool = False) -> Dict[str, str]:
    """
    Genera i dati relativi a un P2PK (Pay-to-Public-Key) nello stile dei primissimi indirizzi Bitcoin.
    
    P2PK è uno dei primi tipi di script di output utilizzati in Bitcoin, dove i fondi vengono
    inviati direttamente a una chiave pubblica invece che a un hash della chiave pubblica.
    Questo metodo è stato utilizzato nei primi giorni di Bitcoin, incluso da Satoshi Nakamoto.

    Args:
        network: 'mainnet', 'testnet' o 'regtest' - Specifica la rete Bitcoin da utilizzare
        compressed: Se True, utilizza la chiave pubblica compressa (33 byte),
                    altrimenti utilizza la chiave non compressa (65 byte).
                    Nei primissimi indirizzi si usava la chiave non compressa.

    Returns:
        Un dizionario contenente:
         - 'private_key_hex': chiave privata in formato esadecimale
         - 'wif': chiave privata in formato WIF (Wallet Import Format)
         - 'public_key_hex': chiave pubblica in formato esadecimale
         - 'p2pk_script': lo script P2PK (output script) in formato esadecimale
         - 'network': rete utilizzata
    """
    # Verifica che il network sia supportato
    # Ottiene la configurazione specifica per la rete selezionata
    config = NETWORK_CONFIG.get(network)
    if config is None:
        raise ValueError("Network non supportato. Scegli tra 'mainnet', 'testnet' o 'regtest'.")

    # 1. Generazione della chiave privata a 32 byte (256 bit)
    # In Bitcoin, le chiavi private sono numeri casuali di 256 bit (32 byte)
    # Utilizziamo secrets.token_bytes che genera byte casuali crittograficamente sicuri
    private_key = secrets.token_bytes(32)
    private_key_hex = private_key.hex()  # Conversione in formato esadecimale per leggibilità

    # 2. Derivazione della chiave pubblica dalla chiave privata
    # Utilizziamo la libreria ecdsa con la curva SECP256k1 (la stessa usata da Bitcoin).
    # La chiave pubblica è un punto sulla curva ellittica derivato dalla chiave privata.
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)  # Crea l'oggetto chiave privata
    vk = sk.get_verifying_key()  # Deriva la chiave pubblica (verifying key)
    pubkey_bytes = vk.to_string()  # Questa operazione restituisce 64 byte: 32 per X e 32 per Y

    if compressed:
        # Chiave pubblica compressa: [0x02 o 0x03] + X (33 byte)
        # Nel formato compresso, salviamo solo la coordinata X e un prefisso che indica
        # se Y è pari o dispari. Questo permette di ricostruire Y quando necessario.
        # Se il valore Y è pari, il prefisso sarà 0x02, altrimenti 0x03.
        x = pubkey_bytes[:32]  # Primi 32 byte: coordinata X
        y = pubkey_bytes[32:]  # Secondi 32 byte: coordinata Y
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'  # Determina il prefisso
        public_key = prefix + x  # Chiave pubblica compressa: prefisso + coordinata X
    else:
        # Chiave pubblica non compressa: [0x04] + X + Y (65 byte)
        # Nel formato non compresso, salviamo entrambe le coordinate X e Y con il prefisso 0x04
        # Questo era il formato originale usato nei primi giorni di Bitcoin
        public_key = b'\x04' + pubkey_bytes  # 0x04 + coordinata X + coordinata Y

    public_key_hex = public_key.hex()  # Conversione in formato esadecimale

    # 3. Costruzione dello script P2PK (Pay-to-Public-Key):
    # Lo script P2PK viene costruito inserendo:
    #    - Un opcode di push che indica la lunghezza della chiave pubblica.
    #    - La chiave pubblica stessa.
    #    - L'operazione OP_CHECKSIG (opcode: 0xac) che verifica la firma.
    # Questo script richiede che chi spende fornisca una firma valida per la chiave pubblica.
    push_opcode = bytes([len(public_key)])  # Restituisce 0x41 per una chiave non compressa o 0x21 per compressa
    op_checksig = b'\xac'  # Opcode per OP_CHECKSIG in Bitcoin Script
    p2pk_script = push_opcode + public_key + op_checksig  # Assemblaggio dello script completo
    p2pk_script_hex = p2pk_script.hex()  # Conversione in formato esadecimale

    # 4. Creazione della rappresentazione WIF (Wallet Import Format) della chiave privata.
    # WIF è un formato standard per rappresentare le chiavi private Bitcoin in modo leggibile
    # e include informazioni sul network e se la chiave è per una pubkey compressa.
    # Se la chiave pubblica è compressa, si aggiunge un byte 0x01 alla fine
    if compressed:
        extended_key = config['wif_prefix'] + private_key + b'\x01'  # Aggiunge il flag di compressione
    else:
        extended_key = config['wif_prefix'] + private_key  # Senza flag di compressione

    # Calcolo del checksum: il checksum è il primo blocco di 4 byte della doppia SHA256 della chiave estesa.
    # Il checksum serve a rilevare errori di digitazione quando si inserisce una chiave WIF.
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    # La chiave WIF è la concatenazione della chiave estesa e del checksum, codificata in Base58.
    # Base58 è una variante di Base64 che evita caratteri ambigui (0, O, I, l) e simboli (+, /).
    wif = base58.b58encode(extended_key + checksum).decode()

    # Ritorna un dizionario con tutti i dati generati
    return {
        'private_key_hex': private_key_hex,  # Chiave privata in formato esadecimale
        'wif': wif,                           # Chiave privata in formato WIF
        'public_key_hex': public_key_hex,     # Chiave pubblica in formato esadecimale
        'p2pk_script': p2pk_script_hex,       # Script P2PK in formato esadecimale
        'network': network                    # Rete utilizzata (mainnet, testnet, regtest)
    }

def main():
    """
    Funzione principale che:
      - Richiede all'utente il tipo di rete da usare (mainnet, testnet, regtest).
      - Chiede se utilizzare la chiave pubblica compressa.
      - Genera i dati relativi al P2PK.
      - Visualizza i dati a video.
      - Salva i dati generati in un file JSON.
    
    Questa funzione gestisce l'interazione con l'utente e coordina il processo di generazione
    delle chiavi e dello script P2PK.
    """
    # Richiesta del tipo di rete all'utente
    network = input("Seleziona il tipo di rete (mainnet, testnet, regtest): ").strip().lower()

    # Nei primissimi indirizzi la chiave non compressa era la norma.
    # Richiesta all'utente se utilizzare chiavi compresse
    compressed_input = input("Utilizzare chiavi compresse (s/n): ").strip().lower()
    while compressed_input not in ['s', 'n']:  # Validazione dell'input
        print("Inserisci 's' per sì o 'n' per no.")
        compressed_input = input("Utilizzare chiavi compresse (s/n): ").strip().lower()
    compressed = (compressed_input == 's')  # Conversione della risposta in booleano

    try:
        # Generazione dei dati P2PK chiamando la funzione generate_p2pk
        result = generate_p2pk(network, compressed)
        
        # Visualizzazione dei risultati a schermo
        print("\n--- Risultati ---")
        print("Chiave privata (hex):", result['private_key_hex'])  # Chiave privata in esadecimale
        print("Chiave privata (WIF):", result['wif'])              # Chiave privata in formato WIF
        key_type = "compressa" if compressed else "non compressa"
        print(f"Chiave pubblica ({key_type}, hex):", result['public_key_hex'])  # Chiave pubblica
        print("Script P2PK:", result['p2pk_script'])                # Script P2PK
        
        # Salvataggio dei dati in un file JSON
        # Richiesta del nome del file all'utente
        nome_file = input("\nInserisci il nome del file (senza estensione) per salvare i dati: ").strip()
        if not nome_file:  # Se l'utente non inserisce un nome, usa un default
            nome_file = "dati_p2pk"
            print("Nome del file non valido. Verrà utilizzato il nome di default: dati_p2pk.json")
        if not nome_file.endswith('.json'):  # Aggiunge l'estensione .json se necessario
            nome_file += '.json'
        
        # Scrittura dei dati nel file JSON con indentazione per leggibilità
        with open(nome_file, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"Dati salvati correttamente nel file: {nome_file}")

    except Exception as e:  # Gestione degli errori
        print("Errore:", e)

# Punto di ingresso del programma
# Questo blocco verifica se lo script viene eseguito direttamente (non importato)
if __name__ == '__main__':
    main()
