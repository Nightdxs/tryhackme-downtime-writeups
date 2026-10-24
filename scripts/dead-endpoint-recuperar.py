"""Recupera copias de los JPEG del reto Dead Endpoint; no ejecuta el malware.

Uso: python3 dead-endpoint-recuperar.py CARPETA_CIFRADA CARPETA_SALIDA
Requiere cryptography. El destino debe ser distinto del origen.
"""
from pathlib import Path
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEED = 1792474614662
MASK = (1 << 64) - 1


def derive_key(seed):
    result = bytearray()
    for _ in range(4):
        seed = (seed + 0x9E3779B97F4A7C15) & MASK
        z = seed
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        z ^= z >> 31
        result.extend(z.to_bytes(8, 'little'))
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error('El destino debe ser distinto del origen.')
    args.destination.mkdir(parents=True, exist_ok=True)
    cipher = AESGCM(derive_key(SEED))
    for source in sorted(args.source.glob('*.locked')):
        data = source.read_bytes()
        if len(data) < 48 or data[:4] != b'GPH1':
            raise ValueError(f'Cabecera inesperada: {source}')
        plain = cipher.decrypt(data[16:28], data[48:] + data[28:44], data[:28])
        if len(plain) != int.from_bytes(data[8:16], 'little'):
            raise ValueError(f'Tamaño inesperado: {source}')
        target = args.destination / source.stem
        with target.open('xb') as output:
            output.write(plain)
        print(f'{target}: {len(plain)} bytes; autenticación GCM correcta')


if __name__ == '__main__':
    main()
