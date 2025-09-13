# Costanti Bitcoin
SAT = 100_000_000		        # 1 BTC in satoshi
DUST_LIMIT = 546   		        # dust threshold P2PKH

# Configurazione server Fulcrum/Electrum
FULCRUM_HOST = "127.0.0.1"
FULCRUM_PORT = 50001  		    # 50001 = plaintext, 50002 = TLS
USE_TLS = False
TIMEOUT_S = 10

# File di configurazione
WALLET_JSON = "wallet.json"  	# file con chiave, pubkey, address

# Configurazioni transazione
DEFAULT_FEE_RATE = 1.0  	    # sat/vB

# Input weights in vBytes
INPUT_WEIGHT_P2PKH = 148    	# peso stimato input P2PKH
INPUT_WEIGHT_P2WPKH = 68    	# peso stimato input P2WPKH
INPUT_WEIGHT_P2PK = 114     	# peso stimato input P2PK
INPUT_WEIGHT_P2SH = 520     	# peso stimato input P2SH multisig (3-di-5)
INPUT_WEIGHT_P2WSH = 104    	# peso stimato input P2WSH
INPUT_WEIGHT_P2TR = 57.25   	# peso stimato input P2TR (Taproot)
INPUT_WEIGHT_P2SH_P2WPKH = 91  	# peso stimato input P2SH-P2WPKH (nested SegWit)

# Output sizes in bytes
OUTPUT_SIZE_P2PKH = 34      	# dimensione output P2PKH
OUTPUT_SIZE_P2WPKH = 31     	# dimensione output P2WPKH
OUTPUT_SIZE_P2PK = 35       	# dimensione output P2PK
OUTPUT_SIZE_P2SH = 32       	# dimensione output P2SH
OUTPUT_SIZE_P2WSH = 43      	# dimensione output P2WSH
OUTPUT_SIZE_P2TR = 43       	# dimensione output P2TR (Taproot)
OUTPUT_SIZE_P2SH_P2WPKH = 32 	# dimensione output P2SH-P2WPKH

# Configurazioni rete
MAX_RETRIES = 3
RECEIVE_BUFFER_SIZE = 65536

# Configurazioni debug
DEBUG_MODE = False
VERBOSE_LOGGING = False
