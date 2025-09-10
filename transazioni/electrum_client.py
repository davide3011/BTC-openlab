import json
import socket
import ssl
from typing import Any, Optional

from config import FULCRUM_HOST, FULCRUM_PORT, USE_TLS, TIMEOUT_S, MAX_RETRIES, RECEIVE_BUFFER_SIZE

class ElectrumClient:
    """Client minimale per server Electrum/Fulcrum"""
    
    def __init__(self, host: str = FULCRUM_HOST, port: int = FULCRUM_PORT, 
                 use_tls: bool = USE_TLS, timeout: int = TIMEOUT_S):
        """Inizializza il client Electrum"""
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self._request_id = 0
    
    def _connect(self) -> socket.socket:
        """Crea una connessione socket al server"""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            
            if self.use_tls:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            return sock
        except Exception as e:
            raise ConnectionError(f"Impossibile connettersi a {self.host}:{self.port}: {e}")
    
    def request(self, method: str, params: Any = None) -> Any:
        """Esegue una richiesta JSON-RPC al server"""
        self._request_id += 1
        
        # Prepara il payload JSON-RPC
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or []
        }
        
        payload_str = json.dumps(payload) + "\n"
        
        # Esegue la richiesta con retry
        for attempt in range(MAX_RETRIES):
            try:
                return self._execute_request(payload_str)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    raise RuntimeError(f"Richiesta fallita dopo {MAX_RETRIES} tentativi: {e}")
                continue
    
    def _execute_request(self, payload_str: str) -> Any:
        """Esegue una singola richiesta"""
        sock = self._connect()
        
        try:
            # Invia la richiesta
            sock.sendall(payload_str.encode('utf-8'))
            
            # Riceve la risposta
            response_data = b""
            while not response_data.endswith(b"\n"):
                chunk = sock.recv(RECEIVE_BUFFER_SIZE)
                if not chunk:
                    break
                response_data += chunk
            
            if not response_data:
                raise RuntimeError("Nessuna risposta dal server")
            
            # Decodifica e processa la risposta
            response = json.loads(response_data.decode('utf-8'))
            
            if "error" in response and response["error"]:
                raise RuntimeError(f"Errore server: {response['error']}")
            
            return response.get("result")
            
        finally:
            sock.close()
    
    def get_balance(self, scripthash: str) -> dict:
        """Ottiene il bilancio per uno scripthash"""
        return self.request("blockchain.scripthash.get_balance", [scripthash])
    
    def list_unspent(self, scripthash: str) -> list:
        """Lista gli UTXO per uno scripthash"""
        return self.request("blockchain.scripthash.listunspent", [scripthash]) or []
    
    def get_transaction(self, txid: str, verbose: bool = False) -> Any:
        """Ottiene una transazione per TXID"""
        return self.request("blockchain.transaction.get", [txid, verbose])
    
    def broadcast_transaction(self, raw_tx: str) -> str:
        """Invia una transazione alla rete"""
        return self.request("blockchain.transaction.broadcast", [raw_tx])
    
    def get_fee_estimate(self, blocks: int = 6) -> float:
        """Stima la fee per conferma in N blocchi"""
        try:
            return self.request("blockchain.estimatefee", [blocks])
        except:
            # Fallback se il metodo non è supportato
            return 0.00001  # 1 sat/byte