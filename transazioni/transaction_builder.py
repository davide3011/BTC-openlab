import struct
import math
from typing import List, Tuple, Dict, Any
from ecdsa import SigningKey

from electrum_client import ElectrumClient
from utxo_manager import UTXO
from wallet_utils import Wallet, get_scriptpubkey_for_address
from script_types import get_script_type, is_witness_script, create_scriptcode_p2wpkh
from crypto_utils import vi, read_varint, sha256d, der_low_s, little_endian
from config import DUST_LIMIT

class TransactionInput:
    """Rappresenta un input di transazione"""
    
    def __init__(self, txid: str, vout: int, script_sig: bytes = b"", sequence: int = 0xffffffff):
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence
    
    def serialize(self) -> bytes:
        """Serializza l'input"""
        return (
            little_endian(self.txid) +
            struct.pack("<I", self.vout) +
            vi(len(self.script_sig)) + self.script_sig +
            struct.pack("<I", self.sequence)
        )

class TransactionOutput:
    """Rappresenta un output di transazione"""
    
    def __init__(self, value: int, script_pubkey: bytes):
        self.value = value
        self.script_pubkey = script_pubkey
    
    def serialize(self) -> bytes:
        """Serializza l'output"""
        return (
            struct.pack("<Q", self.value) +
            vi(len(self.script_pubkey)) + self.script_pubkey
        )

class Transaction:
    """Rappresenta una transazione Bitcoin completa"""
    
    def __init__(self, version: int = 1, locktime: int = 0):
        self.version = version
        self.inputs: List[TransactionInput] = []
        self.outputs: List[TransactionOutput] = []
        self.witnesses: List[List[bytes]] = []  # Stack witness per ogni input
        self.locktime = locktime
    
    def add_input(self, txid: str, vout: int, script_sig: bytes = b"", sequence: int = 0xffffffff):
        """Aggiunge un input alla transazione"""
        self.inputs.append(TransactionInput(txid, vout, script_sig, sequence))
        self.witnesses.append([])  # Stack witness vuoto inizialmente
    
    def add_output(self, value: int, script_pubkey: bytes):
        """Aggiunge un output alla transazione"""
        self.outputs.append(TransactionOutput(value, script_pubkey))
    
    def has_witness_data(self) -> bool:
        """Verifica se la transazione ha dati witness"""
        return any(len(stack) > 0 for stack in self.witnesses)
    
    def serialize_without_witness(self) -> bytes:
        """Serializza la transazione senza dati witness"""
        result = struct.pack("<I", self.version)
        result += vi(len(self.inputs))
        
        for inp in self.inputs:
            result += inp.serialize()
        
        result += vi(len(self.outputs))
        for out in self.outputs:
            result += out.serialize()
        
        result += struct.pack("<I", self.locktime)
        return result
    
    def serialize_with_witness(self) -> bytes:
        """Serializza la transazione con dati witness (formato SegWit)"""
        if not self.has_witness_data():
            return self.serialize_without_witness()
        
        # Header con marker e flag SegWit
        result = struct.pack("<I", self.version)
        result += b"\x00\x01"  # marker + flag
        result += vi(len(self.inputs))
        
        # Input (con scriptSig vuoti per SegWit)
        for inp in self.inputs:
            result += inp.serialize()
        
        # Output
        result += vi(len(self.outputs))
        for out in self.outputs:
            result += out.serialize()
        
        # Sezione witness
        for witness_stack in self.witnesses:
            result += vi(len(witness_stack))
            for item in witness_stack:
                result += vi(len(item)) + item
        
        result += struct.pack("<I", self.locktime)
        return result
    
    def serialize(self) -> bytes:
        """Serializza la transazione nel formato appropriato"""
        if self.has_witness_data():
            return self.serialize_with_witness()
        else:
            return self.serialize_without_witness()
    
    def calculate_sizes(self) -> Tuple[int, int, int, int]:
        """Calcola le dimensioni della transazione"""
        stripped = self.serialize_without_witness()
        with_witness = self.serialize_with_witness()
        
        stripped_size = len(stripped)
        total_size = len(with_witness)
        weight = stripped_size * 4 + (total_size - stripped_size)
        vsize = (weight + 3) // 4
        
        return vsize, weight, stripped_size, total_size

class TransactionBuilder:
    """Costruttore di transazioni Bitcoin"""
    
    def __init__(self, client: ElectrumClient):
        self.client = client
    
    def parse_transaction_outputs(self, raw_hex: str) -> List[Tuple[int, bytes]]:
        """Estrae tutti gli output da una transazione raw"""
        b = bytes.fromhex(raw_hex)
        i = 0
        
        # Version
        i += 4
        
        # Controlla se è SegWit
        has_witness = (i + 2 <= len(b) and b[i] == 0 and b[i + 1] != 0)
        if has_witness:
            i += 2  # marker + flag
        
        # Input
        n_in, i = read_varint(b, i)
        for _ in range(n_in):
            i += 32  # prev txid
            i += 4   # vout
            slen, i = read_varint(b, i)
            i += slen  # scriptSig
            i += 4     # sequence
        
        # Output
        n_out, i = read_varint(b, i)
        outputs = []
        for _ in range(n_out):
            value = int.from_bytes(b[i:i+8], "little")
            i += 8
            slen, i = read_varint(b, i)
            spk = b[i:i+slen]
            i += slen
            outputs.append((value, spk))
        
        return outputs
    
    def get_prevout_info(self, utxo: UTXO) -> Tuple[int, bytes, bool]:
        """Ottiene informazioni sull'output precedente"""
        raw_hex = self.client.get_transaction(utxo.txid, verbose=False)
        if not isinstance(raw_hex, str):
            raise RuntimeError("Risposta inattesa da get_transaction")
        
        outputs = self.parse_transaction_outputs(raw_hex)
        amount, spk = outputs[utxo.vout]
        
        is_witness = is_witness_script(spk)
        return amount, spk, is_witness
    
    def sign_input_legacy(self, tx: Transaction, input_idx: int, prev_spk: bytes, 
                         wallet: Wallet, sighash_type: int = 1) -> bytes:
        """Firma un input legacy (P2PKH/P2PK)"""
        # Crea preimage per firma legacy
        preimage = struct.pack("<I", tx.version)
        preimage += vi(len(tx.inputs))
        
        # Input con scriptSig appropriati
        for i, inp in enumerate(tx.inputs):
            preimage += little_endian(inp.txid)
            preimage += struct.pack("<I", inp.vout)
            
            if i == input_idx:
                # Input da firmare: usa prev_spk
                preimage += vi(len(prev_spk)) + prev_spk
            else:
                # Altri input: scriptSig vuoto
                preimage += vi(0)
            
            preimage += struct.pack("<I", inp.sequence)
        
        # Output
        preimage += vi(len(tx.outputs))
        for out in tx.outputs:
            preimage += out.serialize()
        
        # Locktime + sighash type
        preimage += struct.pack("<I", tx.locktime)
        preimage += struct.pack("<I", sighash_type)
        
        # Hash e firma
        z = sha256d(preimage)
        
        # Determina il tipo di script e usa la funzione di firma appropriata
        script_type = get_script_type(prev_spk)
        if script_type and script_type.can_sign():
            # Usa la funzione di firma del tipo di script
            return script_type.sign(z, wallet.signing_key, wallet.public_key, prev_spk)
        else:
            # Fallback per P2PKH (compatibilità)
            r, s = wallet.signing_key.sign_digest_deterministic(z, sigencode=lambda r, s, _: (r, s))
            sig = der_low_s(r, s) + bytes([sighash_type])
            return vi(len(sig)) + sig + vi(len(wallet.public_key)) + wallet.public_key
    
    def sign_input_witness(self, tx: Transaction, input_idx: int, prev_spk: bytes, 
                          amount: int, wallet: Wallet, sighash_type: int = 1) -> List[bytes]:
        """Firma un input witness (P2WPKH) secondo BIP143"""
        # BIP143 preimage
        version = struct.pack("<I", tx.version)
        
        # hashPrevouts
        prevouts = b""
        for inp in tx.inputs:
            prevouts += little_endian(inp.txid) + struct.pack("<I", inp.vout)
        hash_prevouts = sha256d(prevouts)
        
        # hashSequence
        sequences = b""
        for inp in tx.inputs:
            sequences += struct.pack("<I", inp.sequence)
        hash_sequence = sha256d(sequences)
        
        # Input corrente
        current_input = tx.inputs[input_idx]
        outpoint = little_endian(current_input.txid) + struct.pack("<I", current_input.vout)
        
        # scriptCode per P2WPKH
        pubkey_hash = prev_spk[2:]  # Rimuove OP_0 + push
        script_code = create_scriptcode_p2wpkh(pubkey_hash)
        
        # hashOutputs
        outputs_data = b""
        for out in tx.outputs:
            outputs_data += out.serialize()
        hash_outputs = sha256d(outputs_data)
        
        # Costruisce preimage BIP143
        preimage = (
            version +
            hash_prevouts +
            hash_sequence +
            outpoint +
            vi(len(script_code)) + script_code +
            struct.pack("<Q", amount) +
            struct.pack("<I", current_input.sequence) +
            hash_outputs +
            struct.pack("<I", tx.locktime) +
            struct.pack("<I", sighash_type)
        )
        
        # Hash e firma
        z = sha256d(preimage)
        r, s = wallet.signing_key.sign_digest_deterministic(z, sigencode=lambda r, s, _: (r, s))
        sig = der_low_s(r, s) + bytes([sighash_type])
        
        # Witness stack: [sig, pubkey]
        return [sig, wallet.public_key]
    
    def build_transaction(self, utxos: List[UTXO], outputs: List[Tuple[int, bytes]], 
                         wallet: Wallet, fee_rate: float) -> Tuple[Transaction, int, int]:
        """Costruisce e firma una transazione completa"""
        # Calcola totali
        total_input = sum(u.amount for u in utxos)
        total_output = sum(value for value, _ in outputs)
        
        # Ottiene informazioni sui prevout
        prevout_info = []
        for utxo in utxos:
            amount, spk, is_witness = self.get_prevout_info(utxo)
            prevout_info.append((amount, spk, is_witness))
        
        # Iterazione per calcolo fee ottimale
        fee = 200  # Stima iniziale
        
        for _ in range(10):  # Max 10 iterazioni
            # Calcola resto
            change_amount = total_input - total_output - fee
            
            if change_amount < 0:
                raise ValueError("Fondi insufficienti")
            
            # Crea transazione
            tx = Transaction()
            
            # Aggiunge input
            for utxo in utxos:
                tx.add_input(utxo.txid, utxo.vout)
            
            # Aggiunge output principali
            for value, spk in outputs:
                tx.add_output(value, spk)
            
            # Aggiunge resto se significativo
            has_change = change_amount >= DUST_LIMIT
            if has_change:
                change_spk = get_scriptpubkey_for_address(wallet.address, wallet.hash160)
                tx.add_output(change_amount, change_spk)
            
            # Firma input
            for i, (utxo, (amount, prev_spk, is_witness)) in enumerate(zip(utxos, prevout_info)):
                if is_witness:
                    # Input SegWit
                    witness_stack = self.sign_input_witness(tx, i, prev_spk, amount, wallet)
                    tx.witnesses[i] = witness_stack
                    # ScriptSig rimane vuoto per SegWit
                else:
                    # Input legacy
                    script_sig = self.sign_input_legacy(tx, i, prev_spk, wallet)
                    tx.inputs[i].script_sig = script_sig
            
            # Calcola dimensioni e fee
            vsize, _, _, _ = tx.calculate_sizes()
            new_fee = math.ceil(vsize * fee_rate)
            
            if new_fee == fee:
                break
            
            fee = new_fee
        
        final_change = change_amount if has_change else 0
        return tx, fee, final_change

def create_transaction_builder(client: ElectrumClient) -> TransactionBuilder:
    """Factory function per creare un TransactionBuilder"""
    return TransactionBuilder(client)

def build_transaction(client: ElectrumClient, wallet: Wallet, utxos: List[UTXO], 
                     outputs: List[Tuple[int, bytes]], fee_rate: float) -> Tuple[Transaction, int, int]:
    """Funzione wrapper per costruire una transazione"""
    builder = TransactionBuilder(client)
    return builder.build_transaction(utxos, outputs, wallet, fee_rate)