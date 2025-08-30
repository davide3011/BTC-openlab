# Fulcrum — Server Electrum ad alte prestazioni

## Cos’è Fulcrum
**Fulcrum** è un’implementazione ad alte prestazioni del **protocollo Electrum** per Bitcoin. È un sostituto *drop‑in* di server come ElectrumX/ Electrs, scritto in C++ e ottimizzato per risposte rapide ai wallet.

### Cos’è un *server Electrum*
Un **server Electrum** è un ponte tra i client (wallet) e un nodo Bitcoin Core. Espone un’API JSON-RPC su TCP/SSL per:
- indicizzare blockchain e mempool utili ai wallet;
- rispondere a richieste su **stati degli indirizzi** (via *scripthash*), **bilanci**, **storici delle transazioni**;
- fornire/validare **prove Merkle** e **headers**;
- recuperare **transazioni** e fare **broadcast** di nuove transazioni;
- notificare variazioni (es. nuovi blocchi, nuove tx) tramite **subscription**.

#### Funzioni chiave lato protocollo (panoramica)
> I nomi mettono in evidenza i metodi tipici del protocollo Electrum usati dai wallet.

- `server.version`, `server.features`, `server.ping`, `server.banner`  
  Info di compatibilità, feature e *keep-alive* del server.
- `blockchain.headers.subscribe`  
  Notifica dei nuovi blocchi (cambio altezza / header tip).
- `blockchain.scripthash.subscribe`, `blockchain.scripthash.get_balance`, `blockchain.scripthash.get_history`, `blockchain.scripthash.listunspent`, `blockchain.scripthash.get_mempool`  
  Stato e storico relativi ad uno *script hash* (indirizzo) del wallet.
- `blockchain.transaction.get`, `blockchain.transaction.get_merkle`, `blockchain.transaction.id_from_pos`  
  Recupero della transazione, prova Merkle, ricerca tx da (height, index).
- `blockchain.relayfee`, `mempool.get_fee_histogram` (se supportato)  
  Informazioni su fee minime / istogramma fee mempool.
- `blockchain.transaction.broadcast`  
  Invio di una nuova transazione alla rete via nodo full.

> **Nota**: l’elenco è orientato ai wallet Bitcoin; alcune varianti/estensioni possono differire tra implementazioni.

---

## Perché Fulcrum

Le alternative sono presentate di seguito esclusivamente per un confronto oggettivo con **Fulcrum**: ne evidenziamo punti di forza e limiti, così da motivare in modo trasparente l'adozione di Fulcrum nei contesti che richiedono **alte prestazioni**, **piena compatibilità** con l'ecosistema Electrum e **operatività/manutenzione semplificata**.

**Electrs (Rust)**
- **Pro**: distribuzione semplice, footprint contenuto, integrazione con stack self‑hosted.
- **Contro**: in scenari di *wallet refresh* con molti indirizzi/UTXO può risultare meno rapido.

**ElectrumX (Python)**
- **Pro**: storico e maturo; ampia documentazione.
- **Contro**: consumo risorse e latenza tendenzialmente più elevati sotto carico.

**Electrum Personal Server (EPS)**
- **Pro**: privato, indicizza solo i tuoi indirizzi (ottimo per uso personale).
- **Contro**: non è pensato per servire client generici (no full index pubblico).

**Perché scegliere Fulcrum**
- Prestazioni elevate nei *refresh* dei wallet.
- Compatibilità *drop‑in* con l’ecosistema Electrum.
- Implementazione moderna e ottimizzata (C++ multi‑thread).

---

## Architettura: come funziona

Fulcrum si appoggia a **Bitcoin Core**:
- **RPC** (porta `<RPC-port>`) per interrogazioni su blocchi, tx, UTXO…
- **ZMQ** (porte `<ZMQ-rawblock-port>`, `<ZMQ-rawtx-port>`, `<ZMQ-hashblock-port>`) per ricevere in tempo reale nuovi blocchi/tx.

Poi mantiene un **database locale** (indice) in `<db-path>` per rispondere ai wallet tramite **TCP** (`<tcp-port>`) e/o **SSL/TLS** (`<ssl-port>`). I client si collegano e invocano i metodi Electrum elencati sopra.

Schema logico:
```
[Wallet Electrum]  ←→  [Fulcrum TCP/SSL]  ←→  [Bitcoin Core RPC/ZMQ]
                                     ↘
                                      [Indice DB Fulcrum]
```

---

## Prerequisiti
- **Bitcoin Core** completamente sincronizzato sulla rete desiderata (`mainnet`/`testnet`/`regtest`).
- RPC attivo e raggiungibile da Fulcrum: host `<ip>` (o `<domain>`) e `<RPC-port>`.
- ZMQ attivo con i 3 topic (rawblock, rawtx, hashblock) su porte raggiungibili.
- OS Linux/Unix o container runtime (Docker/Podman) per l’esecuzione.

Esempio (sulla macchina dove gira Bitcoin Core) in `bitcoin.conf`:
```ini
server=1
rpcbind=<ip>
rpcallowip=<ip-fulcrum>
rpcuser=<rpcuser>
rpcpassword=<rpcpassword>
z mqpubrawblock=tcp://<ip>:<ZMQ-rawblock-port>
z mqpubrawtx=tcp://<ip>:<ZMQ-rawtx-port>
z mqpubhashblock=tcp://<ip>:<ZMQ-hashblock-port>
```
> Sostituisci `<ip-fulcrum>` con l’IP da cui Fulcrum contatterà il nodo (es. IP del container/host).

---

## Installazione

### Docker Compose (consigliata)
`docker-compose.yml` (esempio generico):
```yaml
services:
  fulcrum:
    image: cculianu/fulcrum:latest
    container_name: fulcrum
    restart: unless-stopped
    ports:
      - "<tcp-port>:<tcp-port>"   # TCP Electrum (plain)
      - "<ssl-port>:<ssl-port>"   # SSL/TLS Electrum
    volumes:
      - ./fulcrum.conf:/etc/fulcrum/fulcrum.conf:ro
      - ./data:/var/lib/fulcrum
      - ./ssl:/etc/fulcrum/ssl:ro
    command: ["--conf=/etc/fulcrum/fulcrum.conf"]
```
> Se `<ip>` del nodo Bitcoin Core non è raggiungibile via nome/host standard dal container, usa l’IP reale o imposta una rete Docker dedicata. In Linux, `host.docker.internal` può non essere disponibile: preferisci l’IP dell’host o `network_mode: host` (con cautela).

---

## Configurazione (`fulcrum.conf`) — generica

### Blocchi minimi per partire
```ini
# Rete: mainnet | testnet | regtest
net = <mainnet|testnet|regtest>

# Collegamento a Bitcoin Core (RPC)
bitcoind = <ip|domain>:<RPC-port>
rpcuser = <rpcuser>
rpcpassword = <rpcpassword>
bitcoind_timeout = 30.0
bitcoind_clients = 2

# Indice/DB
datadir = <db-path>

# ZMQ (devono combaciare con bitcoin.conf)
rawblock  = tcp://<ip|domain>:<ZMQ-rawblock-port>
rawtx     = tcp://<ip|domain>:<ZMQ-rawtx-port>
hashblock = tcp://<ip|domain>:<ZMQ-hashblock-port>

# Listen (Electrum)
tcp = 0.0.0.0:<tcp-port>
ssl = 0.0.0.0:<ssl-port>
ssl_cert = /etc/fulcrum/ssl/cert.crt
ssl_key  = /etc/fulcrum/ssl/key.key

# Limiti e performance
threads = 2
max_clients_per_ip = 50
peering = false
announce = false
```

### Parametri utili/avanzati (selezione)
- `hostname = <domain>` — nome host pubblico annunciato ai peer.
- `public_tcp_port = <tcp-port>` / `public_ssl_port = <ssl-port>` — porte pubbliche annunciate (NAT/port‑mapping).
- `peering = true|false` — abilita rete di peer Electrum; `announce = true|false` per l’annuncio pubblico.
- `databasemempool = true|false` — persistenza della mempool nel DB (avvio più rapido, più spazio disco).
- `db_use_fsync = true|false` — trade‑off tra integrità e performance su disco.
- `db_mem_budget = <MB>` — budget memoria per cache indicizzazione.
- `report_services = <bitmask>` — modifica dei bit di servizio annunciati.
- `ws = 0.0.0.0:<ws-port>` / `wss = 0.0.0.0:<wss-port>` — WebSocket (browser/client moderni). Per `wss` servono `wss-cert`/`wss-key`.
- `logs_dir = <path>` e `log_level = <info|debug|warn|error>` — logging.

> Consiglio: parti “conservativo” e alza `threads`, `bitcoind_clients` e il budget DB quando misuri colli di bottiglia.

---

## Tipi di connessione: TCP vs SSL/TLS

### TCP (`<tcp-port>`) — semplice ma in chiaro
- Vantaggio: zero overhead di handshake; utile in LAN fidate o per debug.
- Svantaggio: nessuna cifratura né autenticazione → vulnerabile a MITM.

### SSL/TLS (`<ssl-port>`) — cifrato e autenticato
- Il client verifica il **certificato X.509** del server. Usa sempre **SSL/TLS** su reti non fidate o pubblico.

#### Generare un certificato **autofirmato** (self‑signed)
Per test, LAB o reti private (senza dominio pubblico):
```bash
mkdir -p ./ssl
openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout ./ssl/key.key -out ./ssl/cert.crt \
  -subj "/CN=<domain|ip>" \
  -addext "subjectAltName=DNS:<domain>,IP:<ip>"
```
- Inserisci `ssl_cert = /etc/fulcrum/ssl/cert.crt` e `ssl_key = /etc/fulcrum/ssl/key.key` in `fulcrum.conf`.
- I client potrebbero chiedere conferma (cert non CA-signed); per evitare warning, importa la CA o usa un certificato pubblico.

#### Certificato pubblico (Let’s Encrypt)
- Richiede un **<domain>** che punti al tuo server e porte pubbliche per la challenge (HTTP‑01) o accesso DNS (DNS‑01).
- Puoi terminare TLS su **reverse proxy** (Nginx/Caddy) e fare *forward* verso Fulcrum su TCP locale.

---

## Avvio e verifica

### Avvio
- **Docker**: `docker compose up -d`
- **Standalone**: `./Fulcrum --conf=/percorso/fulcrum.conf`

### Test con strumenti di base
- **TCP**: `nc -vz <ip|domain> <tcp-port>`
- **SSL**: `openssl s_client -connect <ip|domain>:<ssl-port> -servername <domain>`
  - Verifica *CN/SAN* e catena certificato.

### Collegare un wallet Electrum (desktop)
1. Impostazioni → Rete → Server manuale.
2. Server: `<ip|domain>`; Porta: `<ssl-port>`; **SSL attivo**.
3. Disattiva la selezione automatica dei server e salva.

---

## Buone pratiche di sicurezza
- Preferisci **SSL/TLS** anche in LAN.
- Se esposto su Internet: certificato **CA‑signed**, firewall, rate‑limit, `max_clients_per_ip`, aggiornamenti regolari.
- Isola Fulcrum e Bitcoin Core su **reti dedicate**; limita l’accesso RPC a IP specifici.
- Backup periodico di `<db-path>` e dei file in `./ssl` (gestione sicura della **chiave privata**!).

---

## Troubleshooting
- **Non si connette a Bitcoin Core (RPC)**: verifica `<ip>`/`<RPC-port>`, credenziali `<rpcuser>/<rpcpassword>`, `rpcallowip` lato `bitcoin.conf`.
- **ZMQ “silenzioso”**: porte e topic devono combaciare. Controlla firewall e che Bitcoin Core stia pubblicando correttamente.
- **SSL fallisce**: percorsi `ssl_cert`/`ssl_key`, permessi file, e *SubjectAltName* che includa `<domain>`/`<ip>` usati dai client.
- **Lento al primo avvio**: l’indicizzazione iniziale può richiedere tempo; successivamente i tempi migliorano.
- **In Docker non risolve l’host**: usa l’IP reale o `network_mode: host` (valuta i rischi). In alternativa, crea una rete Docker e definisci nomi servizio.

---

## FAQ
**Posso usare solo TCP?**  
Sì, ma è sconsigliato fuori da reti fidate.

**Serve per forza un dominio?**  
No, puoi usare IP e certificato self‑signed; i client mostreranno un avviso a meno di CA custom.

**Quanta RAM/Storage servono?**  
Dipende dalla rete (`mainnet` vs `testnet`) e dalle opzioni DB. Pianifica spazio su disco per l’indice (decine di GB su mainnet) e RAM sufficiente per cache.

**Fulcrum sostituisce Bitcoin Core?**  
No: Fulcrum ha bisogno di un nodo **Bitcoin Core** completo per funzionare.

---

## Appendice — Riferimento metodi Electrum (rapido)
| Categoria | Metodo | Scopo |
|---|---|---|
| Server | `server.version`, `server.features`, `server.ping`, `server.banner` | Compatibilità, feature, ping, messaggio server |
| Headers | `blockchain.headers.subscribe` | Notifiche nuovi blocchi |
| Address/Script | `blockchain.scripthash.subscribe`, `...get_balance`, `...get_history`, `...listunspent`, `...get_mempool` | Stato/bilancio/storico UTXO/tx di uno script |
| Transazioni | `blockchain.transaction.get`, `...get_merkle`, `...id_from_pos`, `...broadcast` | Lettura, prove Merkle, ricerca per posizione, broadcast |
| Fee | `blockchain.relayfee`, `mempool.get_fee_histogram`* | Fee minime / istogramma mempool (*se supportato*) |

---

## Licenza

Questo progetto è rilasciato con licenza MIT.

