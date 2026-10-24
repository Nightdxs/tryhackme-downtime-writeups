# Analisis estatico: no ejecuta el payload. Usar en analysis-python.
import glob, base64, io, zipfile
from Crypto.Cipher import AES

d = open(glob.glob('/tmp/day/pid.6260.vad.*.dmp')[0], 'rb').read()
# Inmediatos de las instrucciones PUSH, reconstruidos en orden de pila.
b = b''.join([d[i+1:i+5] for i in range(0x8d, 0x529, 5)][::-1])
c = bytes((x - 0x25) % 256 for x in b)
s = base64.b64decode(c.split()[-1]).decode('utf-16le')
print(s)
k = base64.b64decode(s.split("'")[1])
print(k.hex())

r = open(glob.glob('/tmp/day/*review-cache.dat.dat')[0], 'rb').read()
z = AES.new(k, AES.MODE_CBC, r[:16]).decrypt(r[16:])
# El archivo recuperado incluye relleno de páginas después del ZIP.
a = zipfile.ZipFile(io.BytesIO(z))
print(a.read('release/approval.txt').decode())
