# Costanti Bitcoin
SAT = 100_000_000			# 1 BTC in satoshi
DUST_LIMIT = 546   			# dust threshold

# Configurazione server Fulcrum/Electrum
FULCRUM_HOST = "127.0.0.1"
FULCRUM_PORT = 50001  		# 50001 = tcp, 50002 = TLS
USE_TLS = False
TIMEOUT_S = 10

# File di configurazione
WALLET_JSON = "wallet.json" # file con chiave, pubkey, address

# Configurazioni transazione
DEFAULT_FEE_RATE = 1.0  	# sat/vB
INPUT_WEIGHT_P2PKH = 148  	# peso stimato input P2PKH
INPUT_WEIGHT_P2WPKH = 68  	# peso stimato input P2WPKH
INPUT_WEIGHT_P2PK = 114   	# peso stimato input P2PK
OUTPUT_SIZE_P2PKH = 34    	# dimensione output P2PKH
OUTPUT_SIZE_P2WPKH = 31   	# dimensione output P2WPKH
OUTPUT_SIZE_P2PK = 35     	# dimensione output P2PK

# Configurazioni rete
MAX_RETRIES = 3
RECEIVE_BUFFER_SIZE = 65536

# Configurazioni debug
DEBUG_MODE = False
VERBOSE_LOGGING = False
