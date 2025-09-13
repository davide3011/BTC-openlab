import sys
from typing import Optional

from config import *
from electrum_client import ElectrumClient
from wallet_utils import load_wallet, decode_address, get_scriptpubkey_for_address, select_wallet
from utxo_manager import UTXOManager
from transaction_builder import build_transaction

def main():
    """Main function to handle Bitcoin transaction building and sending."""
    try:
        # 1. Select and load wallet
        print("=== SELEZIONE WALLET ===")
        wallet_file = select_wallet()
        
        print("\nCaricamento wallet...")
        wallet = load_wallet(wallet_file)
        if not wallet:
            sys.exit("Impossibile caricare il wallet!")
        
        print(f"Wallet caricato: {wallet.address}")
        
        # 2. Connect to Fulcrum/Electrum server
        print(f"Connessione a {FULCRUM_HOST}:{FULCRUM_PORT}...")
        client = ElectrumClient(FULCRUM_HOST, FULCRUM_PORT, USE_TLS, TIMEOUT_S)
        
        # 3. Initialize UTXO manager and collect UTXOs
        print("Raccolta UTXO...")
        utxo_manager = UTXOManager(client)
        utxos = utxo_manager.collect_utxos_for_wallet(wallet.hash160, wallet=wallet)
        
        if not utxos:
            sys.exit("Nessun UTXO disponibile!")
        
        # Display available UTXOs
        print("\n--- UTXO Disponibili ---")
        total_balance = 0
        for i, utxo in enumerate(utxos, 1):
            print(f"{i}. {utxo.txid}:{utxo.vout} → {utxo.amount:,} sat")
            total_balance += utxo.amount
        print(f"Bilancio totale: {total_balance:,} sat ({total_balance/SAT:.8f} BTC)")
        print("------------------------\n")
        
        # 4. Get user input for transaction details
        dest_addr = input("Indirizzo destinatario: ").strip()
        if not dest_addr:
            sys.exit("Indirizzo destinatario richiesto!")
        
        # Validate destination address
        hash160 = decode_address(dest_addr)
        if not hash160:
            sys.exit(f"Indirizzo destinatario non valido: {dest_addr}")
        
        # Get scriptPubKey for destination
        dest_scriptpubkey = get_scriptpubkey_for_address(dest_addr, hash160)
        
        try:
            send_amount = int(input("Importo da inviare (satoshi): "))
            if send_amount <= 0:
                sys.exit("L'importo deve essere positivo!")
        except ValueError:
            sys.exit("Importo non valido!")
        
        try:
            fee_rate = float(input(f"Fee rate (sat/vB) [default: {DEFAULT_FEE_RATE}]: ") or DEFAULT_FEE_RATE)
            if fee_rate <= 0:
                sys.exit("Il fee rate deve essere positivo!")
        except ValueError:
            sys.exit("Fee rate non valido!")
        
        # Ask for optional message
        message_response = input("Vuoi includere un messaggio nella transazione? (s/N): ").strip().lower()
        op_return_script = None
        if message_response.startswith('s'):
            message_text = input("Inserisci il messaggio: ").strip()
            if message_text:
                # Create OP_RETURN script
                message_bytes = message_text.encode('utf-8')
                if len(message_bytes) > 80:
                    print("Attenzione: il messaggio è troppo lungo (max 80 bytes), verrà troncato.")
                    message_bytes = message_bytes[:80]
                # OP_RETURN (0x6a) + push data
                op_return_script = bytes([0x6a, len(message_bytes)]) + message_bytes
                print(f"Messaggio aggiunto: {message_text[:80]}")
        
        # 5. Select UTXOs for the transaction
        print("\nSelezione UTXO...")
        
        # Determina il peso dell'input in base al tipo di wallet
        if wallet.is_p2sh:
            input_weight = INPUT_WEIGHT_P2SH
        elif wallet.script_type == "p2wpkh":
            input_weight = INPUT_WEIGHT_P2WPKH
        elif wallet.script_type == "p2pk":
            input_weight = INPUT_WEIGHT_P2PK
        else:
            input_weight = INPUT_WEIGHT_P2PKH  # Default per P2PKH e P2TR
        
        selected_utxos = utxo_manager.select_utxos(utxos, send_amount, fee_rate, input_weight)
        
        selected_total = sum(utxo.amount for utxo in selected_utxos)
        print(f"UTXO selezionati: {len(selected_utxos)}")
        print(f"Totale input: {selected_total:,} sat")
        
        # 6. Build and sign the transaction
        print("\nCostruzione transazione...")
        
        # Create outputs list: [(amount, script_pubkey), ...]
        outputs = [(send_amount, dest_scriptpubkey)]
        
        # Add OP_RETURN output if message was provided
        if op_return_script:
            outputs.append((0, op_return_script))  # 0 satoshi for OP_RETURN output
        
        # Build the transaction
        tx_result = build_transaction(
            client=client,
            wallet=wallet,
            utxos=selected_utxos,
            outputs=outputs,
            fee_rate=fee_rate
        )
        
        if not tx_result:
            sys.exit("Errore nella costruzione della transazione!")
        
        raw_tx, actual_fee, change_amount = tx_result
        vsize, weight, stripped_size, total_size = raw_tx.calculate_sizes()
        
        # 7. Display transaction summary
        print("\n=== RIEPILOGO TRANSAZIONE ===")
        print(f"Destinatario: {dest_addr}")
        print(f"Importo: {send_amount:,} sat ({send_amount/SAT:.8f} BTC)")
        if op_return_script:
            # Decode message from OP_RETURN script
            message_length = op_return_script[1]
            decoded_message = op_return_script[2:2+message_length].decode('utf-8', errors='ignore')
            print(f"Messaggio: {decoded_message}")
        print(f"Fee: {actual_fee:,} sat ({actual_fee/vsize:.2f} sat/vB)")
        print(f"Dimensione: {vsize} vB (peso: {weight})")
        print(f"Fee rate inserito: {fee_rate:.2f} sat/vB")
        if change_amount > 0:
            print(f"Resto: {change_amount:,} sat ({change_amount/SAT:.8f} BTC)")
        print(f"Totale speso: {send_amount + actual_fee:,} sat")
        print("\nTransazione raw (hex):")
        print(raw_tx.serialize().hex())
        print("==============================\n")
        
        # 8. Ask for confirmation and broadcast
        confirm = input("Inviare la transazione? [s/N]: ").strip().lower()
        if confirm.startswith('s'):
            print("Invio transazione...")
            try:
                txid = client.broadcast_transaction(raw_tx.serialize().hex())
                print(f"\n✅ Transazione inviata con successo!")
                print(f"TXID: {txid}")
            except Exception as e:
                print(f"\n❌ Errore nell'invio della transazione: {e}")
                sys.exit(1)
        else:
            print("Transazione non inviata.")
            
    except KeyboardInterrupt:
        print("\nOperazione annullata dall'utente.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Errore: {e}")
        if DEBUG_MODE:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Cleanup
        try:
            client.disconnect()
        except:
            pass

if __name__ == "__main__":
    main()
