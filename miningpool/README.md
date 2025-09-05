# ckpool

**ckpool** è un server **Stratum** per il mining di Bitcoin (o chain compatibili). La sua funzione principale è quella di fare da ponte tra i miner e un **full node** (tipicamente `bitcoind`), generando template di blocco tramite RPC e gestendo connessioni, job, logging e statistiche. 

In pratica:
- I miner si collegano al server ckpool tramite protocollo Stratum (porta configurabile, es. 3333).
- ckpool interroga un full node Bitcoin per i template dei blocchi.
- I risultati vengono validati, conteggiati e inseriti direttamente in coinbase verso il tuo indirizzo.

Puoi usarlo in **due modalità**.

Scarica il repository:
```bash
git clone https://bitbucket.org/ckolivas/ckpool.git
```

---
## 1) Compilazione da sorgente

### Vantaggi
- Controllo completo sul processo di build.
- Puoi personalizzare facilmente il codice o i flag di compilazione.

### Svantaggi
- Devi installare manualmente tutte le dipendenze sul sistema host.
- Rischi di "sporcare" il sistema con librerie e pacchetti.
- Più difficile spostare la configurazione su un'altra macchina.

### Compilazione


```bash

# Installa i seguenti pacchetti:
sudo apt-get update && sudo apt-get install -y \
build-essential autoconf automake libtool pkg-config \
libjansson-dev libcurl4-openssl-dev libzmq3-dev \
ca-certificates git

# Clona il repository ckpool
git clone https://bitbucket.org/ckolivas/ckpool.git
cd ckpool


# Genera i file di configurazione se presente autogen.sh
./autogen.sh


# Configura il progetto
./configure


# Compila il codice
make


# Crea la directory dei log
mkdir -p logs


# Avvia ckpool con il tuo file di configurazione
./src/ckpool -c ./ckpool.conf -l 5 -L

```

## 2) Esecuzione tramite Docker

### Vantaggi
- Ambiente isolato: nessuna dipendenza installata sull'host.
- Portabilità: puoi replicare la stessa configurazione su altre macchine.
- Permessi gestiti con `UID:GID`, così i log sono leggibili dal tuo utente.

### Svantaggi
- Richiede Docker e Docker Compose.
- Piccolo overhead di containerizzazione.

### Esecuzione con Docker
Dopo aver scaricato il repository e aggiunto il `Dockerfile` e il `docker-compose.yml`:


1. Imposta i permessi della cartella log:
```bash
sudo chown -R 1000:1000 logs
```

2. Avvia in background:
```bash
docker compose up -d --build
```

3. Attacca per vedere i parametri in tempo reale:
```bash
docker attach ckpool
```
(uscita senza stop: `Ctrl+p` poi `Ctrl+q`)

4. In alternativa:
```bash
docker logs -f ckpool
```

---

## Configurazione - `ckpool.conf`

ckpool richiede un file di configurazione, da montare nel container o usare localmente. Esempio minimale:

```ini
{
"btcd" :  [
	{
		"url" : "<host>:<rpc-port>",
		"auth" : "<rpc-user>",
		"pass" : "<rpc-password>",
		"notify" : true
	}
],
"btcaddress" : "<bitcoin-address>",
"btcsig" : "/<messaggio>/",
"blockpoll" : 100,
"donation" : 2.0,
"nonce1length" : 4,
"nonce2length" : 8,
"update_interval" : 30,
"version_mask" : "1fffe000",
"serverurl" : ["0.0.0.0:3333"],
"mindiff" : 10000,
"startdiff" : 3000,
"maxdiff" : 0,
"zmqblock" : "tcp://<host>:28332",
"logdir": "logs"
}

```
---

## Risoluzione problemi
- **I miner non si collegano**: controlla porta `3333`, firewall e mapping `ports:`.
- **Errore RPC**: verifica che il nodo Bitcoin sia sincronizzato e accessibile.
- **Log vuoti**: assicurati che `-L` sia attivato e che la cartella abbia i permessi giusti.

---

## Comandi rapidi

```bash
# Da sorgente
./src/ckpool -c ./ckpool.conf -l 5 -L

# Con Docker
sudo chown -R 1000:1000 logs
docker compose up -d
docker attach ckpool
```
