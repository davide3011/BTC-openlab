# Guida all'installazione e configurazione di un nodo Bitcoin Core

Benvenuto! Questo documento ti guiderà nell'installazione e nella configurazione di un **nodo Bitcoin Core**.

---

## Cos'è un nodo Bitcoin?

Un **nodo Bitcoin** è un software che partecipa attivamente alla rete Bitcoin e ne costituisce una parte fondamentale. Un nodo:

* Valida blocchi e transazioni, verificando che rispettino le regole del protocollo.
* Memorizza (tutta o in parte) la blockchain, cioè lo storico delle transazioni.
* Propaga nuove transazioni e nuovi blocchi alla rete, contribuendo alla decentralizzazione.
* Consente di interagire con la rete senza dover dipendere da servizi esterni o provider centralizzati.
* Può fungere da backend per wallet, esploratori blockchain o altri servizi che richiedono dati affidabili.

### Vantaggi di avere un nodo proprio

* **Indipendenza**: non ti affidi a terzi per sapere il saldo del tuo wallet o trasmettere transazioni.
* **Privacy**: le tue interrogazioni alla blockchain restano sotto il tuo controllo.
* **Sicurezza**: verifichi personalmente che le regole di Bitcoin vengano rispettate.
* **Contributo alla rete**: più nodi attivi ci sono, più la rete diventa resiliente e distribuita.

Il software più usato per far girare un nodo è **Bitcoin Core**, sviluppato e mantenuto dalla community open source.

---

## 1. Scaricare Bitcoin Core

Il software ufficiale si scarica dal sito **[bitcoin.org](https://bitcoincore.org/en/download/)**.

Troverai versioni per:

* **Linux**
* **Windows**
* **macOS**

**Verifica sempre le firme** per assicurarti che i file scaricati siano autentici (sul sito sono disponibili le istruzioni).

I test di questa guida sono stati effettuati su **Raspberry Pi 5 con Debian 12**. Usare un **single board computer (SBC)** come il Raspberry Pi porta diversi vantaggi:

* Consumo energetico molto ridotto rispetto a un PC tradizionale.
* Hardware economico e facilmente reperibile.
* Dimensioni compatte, perfette per avere un nodo sempre acceso.
* Sistema dedicato al nodo, che non interferisce con l’uso quotidiano del proprio computer principale.

### Esempio installazione su Linux (x86\_64)

```bash
# Sostituisci X.Y.Z con l'ultima versione
wget https://bitcoincore.org/bin/bitcoin-core-X.Y.Z/bitcoin-X.Y.Z-x86_64-linux-gnu.tar.gz
tar -xzf bitcoin-X.Y.Z-x86_64-linux-gnu.tar.gz
cd bitcoin-X.Y.Z/bin
sudo install -m 0755 bitcoind bitcoin-cli bitcoin-tx /usr/local/bin/
```

Dopo l’installazione, puoi verificare con:

```bash
bitcoind --version
```

---

## 2. Dove si trova la configurazione?

Il nodo Bitcoin legge le impostazioni da un file chiamato **`bitcoin.conf`**.

* **Linux/macOS**: `~/.bitcoin/bitcoin.conf`
* **Windows**: `%APPDATA%\Bitcoin\bitcoin.conf`

Se non esiste, puoi crearlo manualmente.

---

## 3. Buone pratiche per `bitcoin.conf`

Scrivere un `bitcoin.conf` da zero può essere complicato: esistono oltre **170 parametri**!

Per aiutarti, puoi usare lo strumento online: **[Bitcoin Core Config Generator di Jameson Lopp](https://jlopp.github.io/bitcoin-core-config-generator/)**.

### Come funziona?

1. Vai sul sito [jlopp.github.io/bitcoin-core-config-generator](https://jlopp.github.io/bitcoin-core-config-generator/).
2. Scegli un **preset** (nodo completo, nodo ridotto/pruned, ecc.).
3. Personalizza i parametri (es. spazio disco, RAM, sicurezza RPC).
4. Copia il file generato e incollalo nel tuo `bitcoin.conf`.

Questo approccio ti garantisce:

* **Configurazione ottimizzata** per il tuo hardware.
* **Sicurezza maggiore**, grazie alle opzioni preimpostate.
* **Risparmio di tempo** evitando errori manuali.

---

## 4. Esempio di configurazione minima

Se vuoi partire subito, ecco un `bitcoin.conf` di base:

```ini
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
txindex=1
## Attiva pruning (550 MB) se hai poco spazio:
# prune=550
## Cache DB in MB (es. utile su macchine con poca RAM):
# dbcache=512
```

### Spiegazione parametri principali:

* `server=1` → abilita l’interfaccia RPC (necessaria per collegarsi con `bitcoin-cli` e altri software).
* `rpcbind` + `rpcallowip` → limita l’accesso RPC al solo computer locale (più sicuro).
* `txindex=1` → mantiene un indice completo delle transazioni (utile se vuoi usare il nodo come backend per altri servizi).
* `prune=550` → conserva solo gli ultimi \~550 MB di blockchain (risparmia spazio disco).
* `dbcache=512` → imposta la cache in RAM (personalizza secondo l’hardware).

---

## 5. Avvio del nodo

Dopo aver creato il file `bitcoin.conf`, puoi avviare il nodo con:

```bash
bitcoind --daemon
```

Verifica lo stato della sincronizzazione:

```bash
bitcoin-cli getblockchaininfo
```

Per seguire i log in tempo reale:

```bash
tail -f ~/.bitcoin/debug.log
```

**Nota:** la prima sincronizzazione può richiedere giorni, a seconda della tua connessione e dell’hardware.

---

## 6. Buone pratiche generali

* **Verifica le firme dei file** quando scarichi Bitcoin Core.
* **Fai backup del wallet** (`wallet.dat`) prima di aggiornare o modificare configurazioni.
* **Non esporre RPC all’esterno** senza autenticazione forte.
* **Aggiorna regolarmente** all’ultima versione di Bitcoin Core.
* Se usi hardware limitato (Raspberry Pi, VPS piccolo), preferisci la modalità **pruned**.

---

## Riferimenti utili

* Download ufficiale: [https://bitcoincore.org/en/download/](https://bitcoincore.org/en/download/)
* Generatore di configurazione: [https://jlopp.github.io/bitcoin-core-config-generator/](https://jlopp.github.io/bitcoin-core-config-generator/)
* Documentazione Bitcoin Core: [https://github.com/bitcoin/bitcoin](https://github.com/bitcoin/bitcoin)
* Panoramica nodi: [https://developer.bitcoin.org/devguide/node.html](https://developer.bitcoin.org/devguide/node.html)

---

✅ Con questo setup avrai un nodo Bitcoin funzionante, sicuro e configurato secondo le tue esigenze. È il primo passo per partecipare attivamente alla rete Bitcoin e costruire strumenti sopra di essa.
