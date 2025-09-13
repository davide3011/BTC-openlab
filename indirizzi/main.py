import subprocess
import sys

def main():
    print("=== GENERATORE INDIRIZZI BITCOIN ===")
    print("Seleziona il tipo di indirizzo:")
    print("1. P2PK")
    print("2. P2PKH")
    print("3. P2SH")
    print("4. P2WPKH")
    print("5. P2TR")
    
    choice = input("Inserisci la tua scelta: ").strip()
    
    scripts = {
        '1': 'p2pk.py',
        '2': 'p2pkh.py', 
        '3': 'p2sh.py',
        '4': 'p2wpkh.py',
        '5': 'p2tr.py'
    }
    
    if choice in scripts:
        try:
            subprocess.run([sys.executable, scripts[choice]], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Errore nell'esecuzione dello script: {e}")
        except KeyboardInterrupt:
            print("\nOperazione interrotta.")
    else:
        print("Scelta non valida.")

if __name__ == '__main__':
    main()