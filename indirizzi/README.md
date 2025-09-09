# Generatore di Indirizzi Bitcoin

Questo programma permette di generare diversi tipi di indirizzi Bitcoin in modo semplice e interattivo. L'output prodotto include chiavi private, chiavi pubbliche, indirizzi e formati WIF, e può essere salvato in file JSON.

Per la verifica della validità degli indirizzi, è stato utilizzato lo strumento esterno [SecretScan](https://secretscan.org/).

Attualmente il programma supporta i seguenti tipi di indirizzi:
- **P2PK (Pay-to-PubKey)**
- **P2PKH (Pay-to-PubKey-Hash)**
- **P2WPKH (Pay-to-Witness-PubKey-Hash, SegWit v0)**
- **P2TR (Pay-to-Taproot, SegWit v1)**

Sono in fase di sviluppo anche:
- **P2SH (Pay-to-Script-Hash)**
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
3. P2WPKH
4. P2TR
```

Dopo aver selezionato un'opzione, lo script dedicato verrà eseguito e guida l'utente attraverso:
- Scelta della rete (mainnet, testnet, regtest)
- Eventuale utilizzo di chiavi compresse/non compresse
- Visualizzazione e salvataggio dei dati in un file `.json`

Ogni script è indipendente (`p2pk.py`, `p2pkh.py`, `p2wpkh.py`, `p2tr.py`) e implementa le regole specifiche del relativo standard Bitcoin.

---

## Tipologie di indirizzi supportati

### 1. P2PK (Pay-to-PubKey)
- **Pro**: molto semplice, rappresenta direttamente la chiave pubblica.
- **Contro**: obsoleto, non compatibile con la maggior parte dei wallet moderni. Espone la chiave pubblica subito alla blockchain.

### 2. P2PKH (Pay-to-PubKey-Hash)
- **Pro**: è lo standard "legacy", molto diffuso, supportato da tutti i wallet ed exchange. Usa Base58.
- **Contro**: gli indirizzi sono più lunghi e le fee di transazione sono più alte rispetto a quelli più moderni (SegWit).

### 3. P2WPKH (SegWit, Bech32)
- **Pro**: riduce le fee grazie al formato SegWit, gli Indirizzi sono più compatti ed è supportato da quasi tutti i wallet moderni.
- **Contro**: non tutti i vecchi servizi accettano Bech32.

### 4. P2TR (Taproot, Bech32m)
- **Pro**: sono i più recenti, con maggiore privacy e flessibilità (supporta script complessi nascosti dietro un singolo indirizzo). Le fee sono basse.
- **Contro**: ancora relativamente nuovo, non supportato da tutti i servizi.

### In sviluppo
- **P2SH (Pay-to-Script-Hash)**: permette indirizzi basati su script arbitrari, molto usato per multisig.
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