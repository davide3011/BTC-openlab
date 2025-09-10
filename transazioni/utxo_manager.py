import math
from typing import List, Dict, Any

from electrum_client import ElectrumClient
from wallet_utils import spk_p2pkh_from_h160, spk_p2wpkh_from_h160
from crypto_utils import scripthash_from_spk
from config import DUST_LIMIT, INPUT_WEIGHT_P2PKH, INPUT_WEIGHT_P2WPKH

class UTXO:
    """Classe che rappresenta un UTXO"""
    
    def __init__(self, txid: str, vout: int, amount: int, height: int = 0):
        """Inizializza un UTXO"""
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.height = height
    
    @property
    def is_confirmed(self) -> bool:
        """Verifica se l'UTXO è confermato"""
        return self.height > 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'UTXO in dizionario"""
        return {
            "txid": self.txid,
            "vout": self.vout,
            "amount": self.amount,
            "height": self.height
        }
    
    def __str__(self) -> str:
        status = "confirmed" if self.is_confirmed else "unconfirmed"
        return f"{self.txid}:{self.vout} → {self.amount} sat ({status})"
    
    def __repr__(self) -> str:
        return f"UTXO({self.txid[:8]}..., {self.vout}, {self.amount})"


class UTXOManager:
    """Gestore per la raccolta e selezione degli UTXO"""
    
    def __init__(self, client: ElectrumClient):
        """Inizializza il gestore UTXO"""
        self.client = client
    
    def collect_utxos_for_spk(self, spk: bytes, include_unconfirmed: bool = True) -> List[UTXO]:
        """Raccoglie UTXO per uno specifico scriptPubKey"""
        scripthash = scripthash_from_spk(spk)
        utxo_list = self.client.list_unspent(scripthash)
        
        utxos = []
        for u in utxo_list:
            height = u.get("height", 0)
            
            # Filtra UTXO non confermati se richiesto
            if not include_unconfirmed and height == 0:
                continue
            
            utxo = UTXO(
                txid=u["tx_hash"],
                vout=u["tx_pos"],
                amount=int(u["value"]),
                height=height
            )
            utxos.append(utxo)
        
        return utxos
    
    def collect_utxos_for_wallet(self, h160: bytes, include_unconfirmed: bool = True, wallet=None) -> List[UTXO]:
        """Raccoglie UTXO per un wallet (P2PKH, P2WPKH e P2PK)"""
        utxos = []
        
        # Se il wallet è P2PK, cerca solo UTXO P2PK
        if wallet and hasattr(wallet, 'address') and len(wallet.address) > 50:  # Chiave pubblica hex
            from script_types import spk_p2pk
            spk_p2pk_script = spk_p2pk(h160)  # h160 contiene la chiave pubblica per P2PK
            utxos.extend(self.collect_utxos_for_spk(spk_p2pk_script, include_unconfirmed))
        else:
            # Raccoglie UTXO P2PKH
            spk_p2pkh = spk_p2pkh_from_h160(h160)
            utxos.extend(self.collect_utxos_for_spk(spk_p2pkh, include_unconfirmed))
            
            # Raccoglie UTXO P2WPKH
            spk_p2wpkh = spk_p2wpkh_from_h160(h160)
            utxos.extend(self.collect_utxos_for_spk(spk_p2wpkh, include_unconfirmed))
        
        # Ordina per valore decrescente
        utxos.sort(key=lambda x: x.amount, reverse=True)
        
        return utxos
    
    def select_utxos(self, utxos: List[UTXO], target_amount: int, 
                     fee_rate: float, input_weight: int = INPUT_WEIGHT_P2PKH) -> List[UTXO]:
        """Seleziona UTXO ottimali per una transazione"""
        # Ordina UTXO per valore decrescente
        sorted_utxos = sorted(utxos, key=lambda x: x.amount, reverse=True)
        
        selected = []
        total_input = 0
        
        # Funzione per stimare la fee
        def estimate_fee(n_inputs: int, n_outputs: int = 2) -> int:
            # Stima conservativa: 10 bytes base + input_weight per input + 34 bytes per output
            estimated_weight = 10 + n_inputs * input_weight + n_outputs * 34
            return math.ceil(estimated_weight * fee_rate)
        
        for utxo in sorted_utxos:
            selected.append(utxo)
            total_input += utxo.amount
            
            # Calcola fee stimata con il numero corrente di input
            estimated_fee = estimate_fee(len(selected))
            
            # Verifica se abbiamo abbastanza fondi
            if total_input >= target_amount + estimated_fee:
                return selected
        
        # Se arriviamo qui, non abbiamo abbastanza fondi
        total_available = sum(u.amount for u in utxos)
        min_fee = estimate_fee(len(utxos))
        raise ValueError(
            f"Fondi insufficienti. Disponibili: {total_available} sat, "
            f"Richiesti: {target_amount + min_fee} sat (target: {target_amount}, fee: {min_fee})"
        )
    
    def calculate_optimal_fee(self, selected_utxos: List[UTXO], target_amount: int, 
                            fee_rate: float, input_weight: int = INPUT_WEIGHT_P2PKH) -> tuple:
        """Calcola la fee ottimale per una transazione"""
        total_input = sum(u.amount for u in selected_utxos)
        n_inputs = len(selected_utxos)
        
        # Calcola fee assumendo 2 output (destinazione + resto)
        estimated_weight_with_change = 10 + n_inputs * input_weight + 2 * 34
        fee_with_change = math.ceil(estimated_weight_with_change * fee_rate)
        
        change_amount = total_input - target_amount - fee_with_change
        
        # Se il resto è sotto la soglia dust, lo aggiungiamo alla fee
        if change_amount < DUST_LIMIT:
            # Ricalcola fee con 1 solo output (senza resto)
            estimated_weight_no_change = 10 + n_inputs * input_weight + 1 * 34
            fee_no_change = math.ceil(estimated_weight_no_change * fee_rate)
            
            # Aggiungi il resto "dust" alla fee
            final_fee = fee_no_change + max(0, change_amount)
            return final_fee, 0, False
        
        return fee_with_change, change_amount, True
    
    def get_balance(self, h160: bytes, include_unconfirmed: bool = True, wallet=None) -> Dict[str, int]:
        """Ottiene il bilancio di un wallet"""
        utxos = self.collect_utxos_for_wallet(h160, include_unconfirmed=True, wallet=wallet)
        
        confirmed = sum(u.amount for u in utxos if u.is_confirmed)
        unconfirmed = sum(u.amount for u in utxos if not u.is_confirmed)
        
        return {
            "confirmed": confirmed,
            "unconfirmed": unconfirmed,
            "total": confirmed + (unconfirmed if include_unconfirmed else 0)
        }
    
    def print_utxos(self, utxos: List[UTXO]) -> None:
        """Stampa una lista di UTXO in formato leggibile"""
        if not utxos:
            print("Nessun UTXO disponibile")
            return
        
        print(f"\n--- UTXO ({len(utxos)} trovati) ---")
        for i, utxo in enumerate(utxos, 1):
            print(f"{i:2d}. {utxo}")
        
        total = sum(u.amount for u in utxos)
        confirmed = sum(u.amount for u in utxos if u.is_confirmed)
        unconfirmed = total - confirmed
        
        print(f"\nTotale: {total} sat")
        if unconfirmed > 0:
            print(f"  Confermati: {confirmed} sat")
            print(f"  Non confermati: {unconfirmed} sat")
        print("-" * 30)

def create_utxo_manager(client: ElectrumClient) -> UTXOManager:
    """Factory function per creare un UTXOManager"""
    return UTXOManager(client)