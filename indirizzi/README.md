# Generatore di Indirizzi Bitcoin

Questo programma permette di generare diversi tipi di indirizzi Bitcoin in modo semplice e interattivo. L'output prodotto include chiavi private, chiavi pubbliche, indirizzi e formati WIF, e può essere salvato in file JSON.

Per la verifica della validità degli indirizzi, è stato utilizzato lo strumento esterno [SecretScan](https://secretscan.org/).

Attualmente il programma supporta i seguenti tipi di indirizzi:
- **P2PK (Pay-to-PubKey)**
- **P2PKH (Pay-to-PubKey-Hash)**
- **P2SH (Pay-to-Script-Hash, con supporto multisig)**
- **P2WPKH (Pay-to-Witness-PubKey-Hash, SegWit v0)**
- **P2TR (Pay-to-Taproot, SegWit v1)**

Sono in fase di sviluppo anche:
- **P2WSH (Pay-to-Witness-Script-Hash)**

---

## Come funziona il programma

Il file principale è `main.py`. Quando viene eseguito, mostra un menu interattivo che consente di scegliere il tipo di indirizzo da generare:

```bash
python main.py
```

Esempio di esecuzione:
```
=== GENERATORE INDIRIZZI BITCOIN ===
Seleziona il tipo di indirizzo:
1. P2PK
2. P2PKH
3. P2SH
4. P2WPKH
5. P2TR
```

Dopo aver selezionato un'opzione, lo script dedicato verrà eseguito e guida l'utente attraverso:
- Scelta della rete (mainnet, testnet, regtest)
- Eventuale utilizzo di chiavi compresse/non compresse
- Visualizzazione e salvataggio dei dati in un file `.json`

Ogni script è indipendente (`p2pk.py`, `p2pkh.py`, `p2sh.py`, `p2wpkh.py`, `p2tr.py`) e implementa le regole specifiche del relativo standard Bitcoin.

---

## Tipologie di indirizzi supportati

### 1. P2PK (Pay-to-PubKey)
- **Standard**: Formato originale di Bitcoin, definito nel whitepaper di Satoshi Nakamoto
- **Formato indirizzo**: Non ha un formato di indirizzo standard, usa direttamente la chiave pubblica
- **Script**: `<pubkey> OP_CHECKSIG`
- **Pro**: molto semplice, rappresenta direttamente la chiave pubblica, dimensioni di transazione minime
- **Contro**: obsoleto, non compatibile con la maggior parte dei wallet moderni. Espone la chiave pubblica subito alla blockchain, vulnerabile agli attacchi quantistici
- **Uso attuale**: Principalmente per coinbase transactions e casi molto specifici

### 2. P2PKH (Pay-to-PubKey-Hash)
- **Standard**: BIP-13 (Base58Check), formato legacy standard
- **Formato indirizzo**: Inizia con '1' (mainnet), 'm' o 'n' (testnet)
- **Script**: `OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG`
- **Codifica**: Base58Check con prefisso 0x00 (mainnet)
- **Pro**: è lo standard "legacy", molto diffuso, supportato da tutti i wallet ed exchange. Protezione contro attacchi quantistici (hash della chiave pubblica)
- **Contro**: gli indirizzi sono più lunghi e le fee di transazione sono più alte rispetto a quelli più moderni (SegWit), dimensioni di transazione maggiori

### 3. P2SH (Pay-to-Script-Hash)
- **Standard**: BIP-16 (Pay to Script Hash), BIP-67 (Deterministic Pay-to-script-hash multi-signature addresses)
- **Formato indirizzo**: Inizia con '3' (mainnet), '2' (testnet/regtest)
- **Script**: `OP_HASH160 <script_hash> OP_EQUAL`
- **Codifica**: Base58Check con prefisso 0x05 (mainnet), 0xC4 (testnet/regtest)
- **Pro**: permette indirizzi basati su script arbitrari, ideale per multisig e contratti complessi. Supportato da tutti i wallet moderni. Maggiore flessibilità e funzionalità avanzate
- **Contro**: le fee sono leggermente più alte rispetto ai singoli indirizzi e richiede la rivelazione dello script al momento della spesa. Dimensioni di transazione maggiori per il redeem script

**Implementazione attuale: Multisig**
Attualmente il supporto P2SH è limitato agli script multisig, che rappresentano il caso d'uso più comune per P2SH.

**Opzioni disponibili per l'utente:**
- **Configurazione m-of-n**: l'utente può scegliere quante firme sono richieste (m) su un totale di chiavi (n)
  - Esempi: 2-of-3, 3-of-5, 1-of-2, ecc.
  - Limite: 1 ≤ m ≤ n ≤ 16
- **Rete**: mainnet, testnet, regtest
- **Chiavi compresse**: opzione per utilizzare chiavi pubbliche compresse (33 byte) o non compresse (65 byte)
- **Ordinamento BIP67**: le chiavi pubbliche vengono automaticamente ordinate per evitare malleabilità

**Funzionalità implementate:**
- Generazione automatica di n coppie di chiavi (privata/pubblica)
- Creazione del redeem script multisig
- Calcolo dell'hash160 del redeem script
- Generazione dell'indirizzo P2SH finale
- Output JSON strutturato con tutti i dati necessari
- Esportazione delle chiavi private in formato WIF
- Salvataggio completo in file JSON per backup e utilizzo futuro

### 4. P2WPKH (SegWit v0, Bech32)
- **Standard**: BIP-141 (Segregated Witness), BIP-173 (Base32 address format)
- **Formato indirizzo**: Inizia con 'bc1q' (mainnet), 'tb1q' (testnet), 'bcrt1q' (regtest)
- **Script**: `OP_0 <pubkey_hash>` (20 bytes)
- **Codifica**: Bech32 con HRP 'bc' (mainnet), 'tb' (testnet), 'bcrt' (regtest)
- **Witness Program**: versione 0, 20 bytes (hash160 della chiave pubblica)
- **Pro**: riduce le fee grazie al formato SegWit (witness data separato), indirizzi più compatti, supportato da quasi tutti i wallet moderni, protezione contro transaction malleability
- **Contro**: non tutti i vecchi servizi accettano Bech32, richiede supporto SegWit

### 5. P2TR (Taproot, SegWit v1, Bech32m)
- **Standard**: BIP-340 (Schnorr Signatures), BIP-341 (Taproot), BIP-342 (Tapscript), BIP-350 (Bech32m)
- **Formato indirizzo**: Inizia con 'bc1p' (mainnet), 'tb1p' (testnet), 'bcrt1p' (regtest)
- **Script**: `OP_1 <taproot_output>` (32 bytes)
- **Codifica**: Bech32m con HRP 'bc' (mainnet), 'tb' (testnet), 'bcrt' (regtest)
- **Witness Program**: versione 1, 32 bytes (tweaked public key)
- **Pro**: sono i più recenti, con maggiore privacy e flessibilità (supporta script complessi nascosti dietro un singolo indirizzo). Le fee sono basse, firme Schnorr più efficienti, aggregazione delle firme
- **Contro**: ancora relativamente nuovo, non supportato da tutti i servizi, complessità implementativa maggiore

### In sviluppo
- **P2SH (Pay-to-Script-Hash)**: permette indirizzi basati su script arbitrari, molto usato per multisig e contratti complessi.
- **P2WSH (Pay-to-Witness-Script-Hash)**: versione SegWit del P2SH, più efficiente e sicura.

---

## Utilizzo pratico

1. Clona o scarica il repository.
2. Assicurati di avere Python 3 installato e i requisiti:
   ```bash
   # Consigliato ambiente virtuale
   python -m venv venv
   source venv/bin/activate

   # Installazione requisiti
   pip install -r requirements.txt
   ```


3. Esegui il programma principale:
   ```bash
   python main.py
   ```
4. Segui le istruzioni sullo schermo per generare e salvare il tuo indirizzo.

I dati saranno salvati in un file `.json` leggibile e riutilizzabile.

---

## LICENZA
Questo progetto è rilasciato sotto licenza MIT