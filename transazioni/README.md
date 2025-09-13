# Tx Builder

## Scopo

## Scopo generale
Questo progetto è un **programma didattico** per comprendere, passo-passo, come:
1) interrogare un server **Electrum/Fulcrum** per ottenere UTXO;
2) **costruire** una transazione Bitcoin con output standard (P2PKH, P2WPKH) e storico (P2PK);
3) **firmare** gli input della transazione;
4) **trasmettere** la transazione in rete;
5) allegare un **messaggio** on-chain usando un output **`OP_RETURN`** (novità del programma).

> **Attenzione**: non è un wallet di produzione. Le chiavi sono conservate in **chiaro** in file JSON; non usare su mainnet con fondi reali. In produzione servirebbero **HD wallet** (BIP32/BIP39) per rotazione indirizzi, backup con seed, xpub watch-only, privacy e sicurezza migliori.

Il programma supporta diversi tipi di script Bitcoin:

### **P2PKH** (*pay-to-pubkey-hash*)
```
OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
```
Il formato **standard** più utilizzato in Bitcoin. L'indirizzo contiene l'hash160 della chiave pubblica, che viene rivelata solo al momento della spesa. Usa indirizzi **Base58** con prefisso `1` (mainnet), `m`/`n` (testnet/regtest). Utilizza firme **ECDSA** in formato **DER** con codifica **low-S** secondo **BIP66**, con preimage di firma legacy che include la versione, input/output e nSequence. La firma viene concatenata con il byte `SIGHASH_ALL (0x01)` per proteggere l'intera transazione.

### **P2WPKH** (*pay-to-witness-pubkey-hash*)
```
OP_0 <20-byte-pubkey-hash>
```
Versione **SegWit v0** (Segregated Witness) di P2PKH, introdotta con **BIP141/143/144**. Questo formato offre diversi vantaggi:

- **Fee ridotte**: separa i dati witness (firme e chiavi pubbliche) dal calcolo della dimensione base della transazione. Il witness ha un "peso" ridotto (1 invece di 4), risultando in fee minori rispetto a P2PKH legacy.

- **Malleabilità risolta**: il TXID esclude i dati witness, rendendolo immutabile da terze parti. Questo risolve il problema della malleabilità delle transazioni, fondamentale per protocolli Layer-2 come Lightning Network.

- **Indirizzi Bech32**: utilizza il formato nativo `bc1q`/`tb1q`/`bcrt1q` (BIP173) che offre:
  - Migliore rilevamento errori
  - Case-insensitive
  - QR code più compatti
  - Codifica più efficiente (32 bit vs 40 bit di Base58)

- **Script più semplice**: lo script è ridotto a:
  ```
  OP_0 <20-byte-pubkey-hash>
  ```
  mentre i dati di firma vanno nel witness stack separato:
  ```
  [signature, public_key]
  ```

- **Preimage di firma BIP143**: utilizza un nuovo algoritmo di hashing che include esplicitamente gli importi degli input, migliorando sicurezza e efficienza della firma.

### **P2PK** (*pay-to-pubkey*)
```
<pubkey> OP_CHECKSIG
```
Le **prime transazioni** di Bitcoin (specialmente alcune coinbase e pagamenti iniziali) erano P2PK. Oggi questo formato è **in disuso** ma mantenuto per scopi **didattici**.

### **P2SH Multisig** (*pay-to-script-hash multifirma*)
```
OP_HASH160 <script_hash> OP_EQUAL
```
Supporta transazioni **multifirma** (es. 2-di-3) dove sono richieste **m** firme su **n** chiavi totali. Il `redeemScript` contiene la logica multisig:
```
OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
```

### **P2TR** (*pay-to-taproot*)
```
OP_1 <32-byte-output-key>
```
Supporta **Taproot** (SegWit v1), l'upgrade più recente di Bitcoin che introduce numerosi miglioramenti:

- **Privacy migliorata**:
  - Le transazioni key-path sono indistinguibili da quelle script-path
  - Gli script alternativi rimangono nascosti finché non vengono usati
  - Le firme Schnorr permettono key/signature aggregation

- **Efficienza superiore**:
  - Firme **Schnorr** di 64 byte (vs 70-72 byte ECDSA)
  - Batch verification più veloce delle firme
  - Script più compatti grazie al MAST (Merklized Alternative Script Trees)

- **Nuove possibilità**:
  - Script complessi con costi ridotti grazie al MAST
  - Threshold signatures native con Schnorr
  - Cross-input signature aggregation (futura)

Implementa i seguenti BIP:
- **BIP340**: introduce le firme Schnorr
  - Deterministiche (no random k)
  - Linearità per aggregazione
  - Batch verification nativa
  
- **BIP341**: definisce la struttura Taproot
  - Key-path: spesa diretta con chiave tweaked
  - Script-path: script alternativi in Merkle tree
  - Nuovo sighash per migliore sicurezza
  
- **BIP342**: nuovo linguaggio script Tapscript
  - Opcode ottimizzati
  - 32-byte points
  - Limiti script aumentati

Utilizza **Bech32m** (BIP350) per indirizzi che iniziano con:
- `bc1p` (mainnet)
- `tb1p` (testnet)
- `bcrt1p` (regtest)

> **Limitazione P2TR**: attualmente il supporto Taproot è limitato a **transazioni semplici** che utilizzano solo il key-path spending (spesa diretta con la chiave). Non sono ancora implementati:
> - **Script-path spending**: la possibilità di spendere usando script alternativi
> - **Merkle trees**: strutture ad albero per organizzare script multipli
> - **Script complessi**: condizioni di spesa più elaborate oltre alla semplice firma
>
> Questo significa che al momento si possono creare solo transazioni Taproot base con firma singola, senza la flessibilità degli script complessi che Taproot permette nativamente.

---
## Perché servono gli **HD wallet**
- **HD (BIP32/BIP39)** consentono: rotazione automatica indirizzi (niente riuso), separazione ricevute/change (`m/.../change/index`), xpub per wallet watch-only, backup tramite **seed**.
- **Rischi modello attuale**:
  - *Pubkey esposta*: in P2PK (e alla spesa in P2PKH/P2WPKH) la pubkey appare on-chain; è normale, ma in P2PK è anticipata.
  - *Riuso indirizzi/chiavi*: peggiora la privacy. Gli HD generano sempre nuovi indirizzi.
  - *Chiavi in chiaro nel JSON*: solo per laboratorio.

---

## Novità: messaggio on-chain via **`OP_RETURN`**
É possibile allegare un **messaggio** (UTF-8) tramite un output `OP_RETURN` **non spendibile**:

```
OP_RETURN <PUSHDATA>
```

- Valore dell'output = **0 sat** (evita dust; compatibile con le policy di standardness più diffuse).
- **Troncatura** automatica a ~**80 byte**.
- Aumenta la **dimensione** della tx (quindi la fee), ma non influenza la logica di firma degli input.

> **Roadmap:** in lavorazione il supporto a **P2WSH** e **script-path spending** per Taproot (Merkle trees e script complessi).

---

## Panoramica
- **`main.py`** guida l'utente passo passo: selezione wallet > connessione al server > raccolta UTXO > input utente (indirizzo, importo, fee, messaggio) > costruzione e firma > riepilogo > invio.

- **`electrum_client.py`** parla con un server **Fulcrum/Electrum** via JSON-RPC (`blockchain.scripthash.*`, `blockchain.transaction.*`).

- **`utxo_manager.py`** calcola lo **scripthash** dagli scriptPubKey, interroga il server e seleziona gli UTXO adeguati.

- **`transaction_builder.py`** costruisce la transazione, calcola fee/vsize, gestisce **OP_RETURN**, aggiunge **resto** se sopra la dust-limit e firma:
  - **Legacy (P2PKH/P2PK)** con preimage legacy + firma DER low-S.
  - **SegWit (P2WPKH)** con preimage **BIP143** e witness stack `[sig, pubkey]`.
  - **P2SH Multisig** con redeemScript e firme multiple.
  - **Taproot (P2TR)** con preimage BIP341 e firma Schnorr (solo key-path spending).

- **`wallet_utils.py`** loads wallets from JSON, validates/decodes addresses (Base58/Bech32/Bech32m) and public keys (P2PK/P2TR). Handles key derivation and tweaking for Taproot.

- **`script_types.py`** generates scriptPubKey and corresponding signers for all supported types (P2PKH, P2WPKH, P2PK, P2SH multisig, P2TR). Includes Taproot key-path spending.

- **`crypto_utils.py`** contains cryptographic utilities: double SHA256, VarInt, DER low-S encoding, Bech32/Bech32m encoding/decoding, Schnorr signatures, tagged hashes for BIP340/341.

---

## Flusso logico

```
Utente ─ main.py ─ ElectrumClient ── (Fulcrum/Electrum)
   |            |                 |           └─ Blockchain (UTXO, tx previe, broadcast)
   |            |                 └─ UTXOManager (scripthash, raccolta e selezione UTXO)
   |            └─ wallet_utils (wallet JSON, decode addr/pubkey, scriptPubKey)
   |            └─ transaction_builder (costruzione tx, firme, vsize/fee, OP_RETURN, resto)
   └─────── Console: riepilogo + raw hex + (opz.) TXID
```

### 1) Selezione e caricamento wallet
- `select_wallet()` cerca `*.json`, li elenca, e restituisce il file scelto.
- `load_wallet(path)` crea un oggetto `Wallet(private_key, public_key, address, hash160)`.
  - Per **P2PK**, `address` è la **chiave pubblica hex**; `decode_address()` la riconosce e la passa come bytes al builder di `scriptPubKey` P2PK.

### 2) Connessione al server Electrum/Fulcrum
- `ElectrumClient(host, port, use_tls)` apre il socket (opz. TLS) e fornisce `request(method, params)` con retry/timeout.

### 3) Raccolta UTXO del wallet
- Costruiamo gli `scriptPubKey` applicabili alla stessa chiave (P2PKH, P2WPKH, P2TR e, se wallet è P2PK, anche P2PK).
- Per ciascuno, calcoliamo lo **scripthash** (SHA256 dello `scriptPubKey`, little-endian) e chiamiamo `blockchain.scripthash.listunspent`.
- Gli elementi sono mappati in `UTXO(txid, vout, amount, height, scriptPubKey)` con il formato di output originale.
- Supporta anche UTXO multifirma P2SH se il wallet contiene le chiavi necessarie.

### 4) Input utente
- **Destinatario**: indirizzo Base58/Bech32/Bech32m **oppure** **pubkey hex** (per inviare a **P2PK**). Supporta:
  - Legacy Base58 (`1`/`m`/`n`)
  - SegWit Bech32 (`bc1q`/`tb1q`/`bcrt1q`) 
  - Taproot Bech32m (`bc1p`/`tb1p`/`bcrt1p`)
  - Chiave pubblica hex (per P2PK didattico)
- **Importo** in satoshi.
- **Fee rate** (sat/vB) con default da `config.py`.
- **Messaggio opzionale** se presente, viene creato l'output `OP_RETURN` (0 sat, payload UTF-8 = ~80B): `0x6a <len> <bytes>`.

### 5) Selezione UTXO (greedy + stima fee)
- `select_utxos(utxos, target_amount, fee_rate)` ordina per valore e somma finché `totale = importo + fee_stimata`.
- `fee_stimata` usa pesi configurati (`INPUT_WEIGHT_*`, `OUTPUT_SIZE_*`) per stimare `vsize`.

### 6) Costruzione della transazione
- Preleva, per ogni input, i **prevout** (via `blockchain.transaction.get`) per ottenere `amount` e `scriptPubKey` originali.
- Crea gli **output**: destinatario, (opz.) `OP_RETURN`, (opz.) **resto** se ≥ `DUST_LIMIT` (altrimenti aggiunto alla fee).
- **Firma input** secondo il tipo:
  - **Legacy (P2PKH/P2PK)**: costruzione *preimage* legacy, `z = SHA256d(preimage)`, firma ECDSA **DER low-S** `SIGHASH_ALL`, `scriptSig = <sig+hashtype> <pubkey>` (P2PKH) o `<sig+hashtype>` (P2PK).
  - **P2SH Multisig**: firma **m** chiavi del `redeemScript`, `scriptSig = OP_0 <sig1> <sig2> ... <redeemScript>`. Attualmente supporta solo configurazioni 2-di-3.
  - **SegWit v0 (P2WPKH)**: *BIP143* con `hashPrevouts/hashSequence/hashOutputs`, `scriptCode = P2PKH(pubkey_hash)`, witness stack `[sig+hashtype, pubkey]`, `scriptSig` vuoto.
  - **Taproot (P2TR)**: *BIP341* sighash con **key-path spending**, firma **Schnorr** 64-byte, witness stack `[signature]` (no pubkey), `scriptSig` vuoto. Solo spesa key-path implementata.
  - **P2WSH e script-path P2TR**: in sviluppo, non ancora supportati.
- Calcola `vsize/weight` dalla serializzazione effettiva (con e senza witness) e **ricalibra la fee**; itera finché **converge**.
- Supporta la creazione di output `OP_RETURN` con messaggi UTF-8 fino a 80 bytes.

### 7) Riepilogo, serializzazione e (opz.) broadcast
- Mostra: destinatario, importo, fee in sat e **sat/vB**, `vsize`, resto, totale speso, ed **hex** completo (incluso witness se presente).
- Se confermato, invia via `blockchain.transaction.broadcast(raw_hex)` e stampa il **TXID** (per SegWit = hash della serializzazione **senza** witness; il **wtxid** includerebbe il witness).

## Configurazione rapida
Modifica `config.py`:
```py
FULCRUM_HOST = "<ip o hostname>"
FULCRUM_PORT = 50001   # 50002 se TLS
USE_TLS      = False
DEFAULT_FEE_RATE = 1.0 # sat/vB
```
Pesi di stima (input/output) e limiti (es. `DUST_LIMIT`) sono nello stesso file.

### Dipendenze (Python 3.10+)
Dipendenze Python in `requirements.txt`:
```txt
ecdsa>=0.18.0
base58>=2.1.1
```

Installa con:
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Il programma necessita di due componenti:
1. **Server Fulcrum/Electrum**: per interrogare la blockchain e trasmettere le transazioni. > [server Fulcrum](https://github.com/davide3011/BTC-openlab/tree/main/fulcrum)
2. **Un wallet JSON** con il formato idoneo, generato dal programma del repository > [wallet JSON](https://github.com/davide3011/BTC-openlab/tree/main/indirizzi)

---
## Configurazione

Apri **`config.py`** e imposta i parametri principali:

- **Server Fulcrum/Electrum**
  - `FULCRUM_HOST = "127.0.0.1"` IP o hostname del tuo server (es. locale)
  - `FULCRUM_PORT = 50001` 50001 **TCP**, 50002 **TLS**
  - `USE_TLS = False` usa `True` se usi porta TLS (50002)
  - `TIMEOUT_S = 10` timeout socket (s)

- **Transazioni e stime**
  - `DEFAULT_FEE_RATE = 1.0`        > sat/vB predefiniti (puoi sovrascriverli a runtime)
  - `DUST_LIMIT = 546`               > soglia dust per P2PKH
  - Pesi stimati input/output (P2PKH, P2WPKH, P2PK) per la stima fee.

> **Rete effettiva**: dipende dal **server** a cui ti connetti. Il campo `network` nel wallet JSON è **informativo**. Se connetti Fulcrum su **regtest**, anche il wallet deve riferirsi a UTXO di regtest, altrimenti non troverai fondi nè potrai trasmettere. Analogo per testnet/mainnet.

---

## Preparare un wallet JSON
Esempio di **wallet P2PKH** per **regtest** (che dovrà essere salvato all'interno della directory del progetto):
```json
{
  "network": "regtest",
  "script_type": "p2pkh",
  "private_key_hex": "b3393af15c3e85bfcfa2d78eb0f0f11f2726782fb934c561e9c545db065d992b",
  "private_key_wif": "cTb6725NJ7cLfC5L24HB7Gqhm5GkD1msB2JgmW6Ra2fyDoVjGVPf",
  "public_key_hex": "020234b95ff14106091e26d1e5ed24511d347119339502e1550a7634299adf3048",
  "address": "mj7FAz7eTq23UYp5oZFga6oDa6vEHJ5xpy"
}
```

Sono supportati:
- **P2PKH** (legacy, Base58)
- **P2WPKH** (SegWit v0, Bech32 `bc1q`/`tb1q`/`bcrt1q`)
- **P2PK** (chiave pubblica in esadecimale come "indirizzo")
- **P2SH Multisig** (script multifirma, Base58 con prefisso `3`/`2`)
- **P2TR** (Taproot, Bech32m `bc1p`/`tb1p`/`bcrt1p`)

> Puoi avere **più file `.json`**: all'avvio ti verrà chiesto di **selezionare** quale usare.


---

## Come usare il programma
1. **Attiva l'ambiente** ed installa le dipendenze (vedi sopra).
2. **Configura** `config.py` con host/porta/TLS corretti per la tua rete.
3. **Prepara** uno o più **wallet JSON** con (assicurati di avere del saldo).
4. **Avvia** il programma:
   ```bash
   python main.py
   ```
5. **Seleziona il wallet** dalla lista proposta.
6. Il programma **si connette** al server e **raccoglie gli UTXO** (mostra bilancio e dettaglio UTXO).
7. Inserisci:
   - **Indirizzo destinatario** (Base58/Bech32/Bech32m o **pubkey hex** per P2PK didattico)
   - **Importo** in **satoshi**
   - **Fee rate** in **sat/vB** (premi `Invio` per usare `DEFAULT_FEE_RATE`)
   - **Messaggio opzionale**: se rispondi "s", aggiunge un **output OP_RETURN** (0 sat) con max **80 byte**
   - **Conferma**: rivedi i dettagli e conferma con "s" per procedere
8. Il programma **seleziona** gli UTXO, **costruisce e firma** la transazione.
9. Vedi il **riepilogo**: destinatario, importo, eventuale messaggio, **fee** (sat e sat/vB), **vsize**, **resto**, **raw hex**.
10. Conferma: `Inviare la transazione? [s/N]` scrivi **`s`** per **trasmettere**. In caso positivo viene mostrato il **TXID**.

---

## Licenza
Rilasciato con licenza **MIT**.