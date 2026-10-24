# It's Downtime! - TryHackMe Writeups
Nighmar3 · CiberSecUNI

Ocho retos: triage SOC, threat hunting, respuesta a incidentes y análisis forense.

[PDF (primera versión)](WRITEUP.pdf) · [Scripts](scripts) · [Capturas y evidencias](evidencias) · [Guía del paquete](LEEME.md)

## Contenido

- [00. Antes de empezar](#reto-00)
- [01. Repossessed: triage de alertas SOC](#reto-01)
- [02. Quiet As The Grave: reconstrucción de la intrusión](#reto-02)
- [03. Deadmen Tell No Logs: decisiones de respuesta](#reto-03)
- [04. Handbook for the Recently Compromised](#reto-04)
- [05. The Waiting Room: adjunto, ejecución y documento transferido](#reto-05)
- [06. Day-O: de memoria ejecutable a caché descifrada](#reto-06)
- [07. Strange & Unusual Activity: C2 entre tráfico legítimo](#reto-07)
- [08. Dead Endpoint: recuperación del ransomware](#reto-08)
- [09. Notas finales](#reto-09)

<a id="reto-00"></a>

## 00. Antes de empezar

Aquí dejamos las notas de los ocho retos de It's Downtime!: qué encontramos, qué comandos usamos y cómo salieron las respuestas. Las capturas son de la resolución y los scripts están en el repositorio.

Limpiamos los comandos para que se puedan copiar sin arrastrar los errores de tecleo de la terminal. Los recortes de pantalla están indicados; también guardamos las imágenes completas.

| Reto | Resultado observado | Evidencia disponible |
|---|---|---|
| Repossessed | 9 alertas cerradas; TP y FP al 100 % | Captura de evaluación y alertas visibles |
| Quiet As The Grave | Investigación exitosa; 998 puntos | Captura final y cronología documentada |
| Deadmen Tell No Logs | 143/150 puntos | Conclusión narrativa del tabletop |
| Handbook for the Recently Compromised | 100 %; 5 respuestas aceptadas | Respuestas reconsultadas y extracto EVTX |
| The Waiting Room | 100 %; 6 respuestas aceptadas | Respuestas reconsultadas y captura final |
| Day-O | 100 %; 7 respuestas aceptadas | Memoria analizada, comandos y captura técnica |
| Strange & Unusual Activity | 100 %; 5 respuestas aceptadas | Registros Zeek, consultas y captura técnica |
| Dead Endpoint | 100 %; 6 respuestas aceptadas | Disco, desensamblado, recuperación autenticada y checklist |

### Sobre estas notas

Cada reto tiene sus propias fechas. Las horas de las tablas pertenecen a los registros del laboratorio, no al día en que resolvimos el evento.

De Repossessed y del tabletop conservamos sobre todo la evaluación final. De The Waiting Room tenemos las respuestas verificadas, pero faltan las notas completas de la extracción. En esos apartados dejamos claro hasta dónde se puede reconstruir el proceso.

<a id="reto-01"></a>

## 01. Repossessed: triage de alertas SOC

### Las alertas

El escenario arranca cuando Marketing abre un press kit sospechoso. Había nueve alertas que revisar: procesos, conexiones, enumeración y actividad remota.

Un detalle útil de este reto: la misma regla aparece entre los verdaderos y los falsos positivos. Pasa con los procesos hijo sospechosos y con las conexiones posteriores a una compresión. Había que mirar qué proceso lo había provocado y qué ocurría alrededor.

### Clasificaciones guardadas

| ID visible | Regla / actividad | Clasificación aceptada |
|---|---|---|
| 6353 | Suspicious Child Process Spawned | Verdadero positivo |
| 6359 | Suspicious Archive Utility Execution on Workstation | Verdadero positivo |
| 6356 | Rapid Domain and Host Enumeration from Non-Administrative Host | Verdadero positivo |
| 6357 | Suspicious Remote Logon and Service Creation | Verdadero positivo |
| 6360 | Suspicious External Connection Following Archive Creation | Verdadero positivo |
| 6352 | Suspicious Child Process Spawned | Falso positivo |
| 6358 | Suspicious External Connection Following Archive Creation | Falso positivo |

Terminamos con nueve alertas cerradas y un 100 % tanto en TP como en FP. En la captura se leen siete clasificaciones, que son las de la tabla. Las otras dos no quedaron visibles en el resumen guardado.

![Figura 1. Recorte de la evaluación: clasificaciones visibles. La captura completa se incluye en el paquete.](evidencias/soc-clasificacion-recorte.png)

![Figura 2. Recorte de métricas: 100 % en TP y FP; nueve alertas cerradas.](evidencias/soc-metricas-recorte.png)

### Qué había que mirar

Lo que conviene llevarse de aquí es esa comparación entre alertas casi iguales: el nombre de la detección no resolvía el caso. Había que seguir el proceso, la cuenta y la conexión asociados.

<a id="reto-02"></a>

## 02. Quiet As The Grave: reconstrucción de la intrusión

### Por dónde empezó la búsqueda

En este escenario seguimos un helper malicioso en un puesto de desarrollo. A partir de él aparecieron la persistencia, las credenciales de servicio y los saltos a otros equipos. Los registros revisados no bastan para precisar cómo llegó el señuelo ni para confirmar que el servidor externo recibió el archivo final.

La investigación terminó con 998 puntos. Hubo un intento anterior fallido; la captura de abajo corresponde a la evaluación final.

### Cronología: 10 de septiembre de 2026, UTC

| Hora | Hallazgo | Evidencia / alcance |
|---|---|---|
| 12:29:48 | Ejecución de review-helper.ps1 en THM-SREYES | Eventos 44850 y 9603; PowerShell desde Explorer |
| 12:37:20 | Copia del helper y clave Run NeuralNexusReview | 9613, 44895 y 44896; relanzamiento a las 12:44:04 |
| 13:01:41 | Lectura de deploy-settings.json | 9628; uso de username/password para PSCredential |
| 13:16:42 | WinRM hacia THM-LSULLIVAN | 9629, 7491, 22097 y 41089; ejecución remota confirmada |
| 13:48:25 | Intento de acceso a DC-01 | 9668 y 9671; AccessDenied, sin ejecución confirmada |
| 14:03:25 | Intento de alterar inventory.ps1 | 9672 y 9677; escritura denegada |
| 15:03:36 | Salto de IT a THM-MSMITH | 9678, 22221, 7653 y 42416 |
| 16:03:37 | Enumeración de usuarios, administradores y recursos | 9687, 42860, 42862 y 42864; algunas consultas denegadas |
| 16:27:28 | Creación de review-cache.zip | 9741 y 9801; staging de material accesible |
| 16:27:54 | curl.exe con --upload-file hacia el C2 | 9807 y 46271; comando de exfiltración observado |

### Seguir los saltos entre equipos

El punto de partida fue THM-SREYES (10.60.10.20), con la cuenta s.reyes ejecutando el helper. El script usaba `https://45.147.230.131:8443` como C2, con las rutas `/register`, `/task` y `/result`, y esperaba 150 segundos entre consultas. Después se copió a AppData Local y añadió una clave Run del usuario.

El siguiente paso salió de `C:\StudioProjects\NeuralNexus\tools\deploy-settings.json`: sus datos permitían construir credenciales para `svc-studioops`. Para comprobar el salto a THM-LSULLIVAN (10.60.10.21), cruzamos el New-PSSession del origen con el logon de red tipo 3 y un hijo de wsmprovhost.exe en destino. Con esa misma comprobación pudimos seguir el salto a THM-MSMITH (10.60.10.22).

Los intentos contra DC-01 y el script de mantenimiento devolvían AccessDenied. En esos casos el comando estaba registrado, pero el acceso había fallado. Tampoco encontramos una elevación exitosa a administrador o SYSTEM.

### Búsquedas usadas

Ojo con `event_id` en estas búsquedas: es el identificador del registro del simulador. No es el Event ID de Windows, como 4624 o 4104.

```text
index=* ComputerName="THM-SREYES" (event_id=44850 OR event_id=9603)
index=* (event_id=9629 OR event_id=7491 OR event_id=22097 OR event_id=41089)
index=* (event_id=9668 OR event_id=9671 OR event_id=22176)
index=* ComputerName="THM-SREYES" (event_id=9741 OR event_id=9801)
index=* ComputerName="THM-SREYES" (event_id=9807 OR event_id=46271)
```

### El ZIP y la subida al C2

Al final se reunieron archivos de `approved-release` de Marketing y `release-notes` del proyecto en un directorio temporal. Se comprimieron como `review-cache.zip` y apareció curl.exe con `--upload-file` hacia `/ingest/review-cache.zip` en el C2. Aquí la prueba llega hasta el comando: no guardamos una respuesta HTTP ni una confirmación de recepción. Tampoco revisamos todo el ZIP como para afirmar que contenía el build completo o los backups.

![Figura 3. Evaluación final de Quiet As The Grave: investigación exitosa, 998 puntos.](evidencias/tryhackme-threat-hunting-aprobado.png)

### Qué revisar después

Como respuesta al incidente, habría que contener los tres equipos y rotar las credenciales de svc-studioops. También revisaríamos los permisos de WinRM y buscaríamos el C2 y la clave Run en el resto del entorno. Son medidas propuestas a partir del caso; el ejercicio consistía en investigar la telemetría.

<a id="reto-03"></a>

## 03. Deadmen Tell No Logs: decisiones de respuesta

### Resultado del ejercicio

La tarjeta del evento lo llama Deadmen Tell No Logs; al terminar, el simulador muestra la categoría Sabotage. La puntuación fue 143/150.

Según el cierre del ejercicio, se consiguió conservar el último punto de restauración verificado antes de perder BAK-01. También se detectó el paquete de lanzamiento saboteado antes de distribuirlo y se avisó al comité de lanzamiento.

El cierre cuenta además que el equipo de crisis gestionó la cuenta de backup comprometida, la comunicación pública y la parte legal. NeuralNexus salió con un build limpio y la suplantación en redes se trató con la plataforma sin más impacto en los clientes.

### Qué quedó guardado

No guardamos el texto de las quince decisiones, así que este apartado recoge el desenlace y la puntuación. No sirve como una lista de opciones para repetir exactamente la partida.

La parte más clara del resultado es el orden de prioridades: conservar una copia que se pueda restaurar, comprobar el paquete y dar al comité información suficiente para decidir sobre el lanzamiento.

![Figura 4. Conclusión narrativa del tabletop y puntuación de 143/150.](evidencias/tryhackme-tabletop-143-150.png)

<a id="reto-04"></a>

## 04. Handbook for the Recently Compromised

### Abrir los EVTX

Los archivos estaban en `~/Desktop/artifacts`: `Microsoft-Windows-Sysmon%4Operational.evtx` y `PowerShell-Operational.evtx`. Usamos Sysmon para seguir los procesos y PowerShell para leer los bloques de script.

```bash
evtx_dump ~/Desktop/artifacts/Microsoft-Windows-Sysmon%4Operational.evtx > /tmp/sysmon.xml
evtx_dump ~/Desktop/artifacts/PowerShell-Operational.evtx > /tmp/powershell.xml
```

La salida completa quedó en las notas locales y no se subió al repositorio. Incluía comandos de preparación del laboratorio además del ataque, así que no bastaba con elegir el primer evento por fecha.

### Cadena confirmada: 2 de octubre de 2026

| Hora UtcTime | Actividad |
|---|---|
| 05:02:05.238 | mshta.exe abre pipeline-check.hta desde Downloads de j.collins |
| 05:02:05.480 | PowerShell oculto resuelve certu*.exe y ordena la descarga |
| 05:02:06.830 | certutil.exe descarga pipeline-sync.ps1 desde pipeline-cdn.thm:8088 |
| 05:02:06.974 | PowerShell ejecuta el script temporal con -ep bypass |
| 05:02:08.209 | schtasks.exe crea StudioPipelineSync para ejecutarse al iniciar sesión |

El comodín era la primera pista: `gci C:\Windows\System32\certu*.exe`. Podía ocultar el nombre en el comando, pero el evento de creación del proceso mostraba `certutil.exe`. En PowerShell también aparecían la petición a `/checkin`, la tarea programada y una escritura a `.sync-cache` con la flag decodificada desde Base64.

Las dos respuestas de MITRE fueron `T1218.005` para mshta y `T1053.005` para la tarea programada. Antes de esta cadena había limpiezas de logs; con lo guardado no pudimos atribuirlas al intruso.

### Respuestas aceptadas

| Campo | Valor |
|---|---|
| Utilidad | `certutil.exe` |
| URL de segunda etapa | `http://pipeline-cdn.thm:8088/pipeline-sync.ps1` |
| Ejecución del adjunto | `T1218.005` |
| Persistencia | `T1053.005` |
| Flag | `THM{tH3_Gh0st_w1tH_Th3_M05T}` |

La flag salió del bloque que construía `$blob`: concatenaba varios literales Base64 y los pasaba por FromBase64String y UTF8.GetString. Para leerla bastaba unir esos literales y decodificarlos con `base64.b64decode`, sin ejecutar el script completo.

<a id="reto-05"></a>

## 05. The Waiting Room: adjunto, ejecución y documento transferido

### El correo y el adjunto

Michelle Smith había recibido un correo de proveedor relacionado con pagos. Tras abrir el adjunto, el equipo contactó un servicio desconocido. Teníamos un EML, eventos Windows y un PCAP para seguir el recorrido.

El reto quedó al 100 %. Al preparar estas notas volvimos a abrir la sala completada para comprobar los hashes, la clave y el resto de las respuestas de la tabla.

### Respuestas

| Campo | Valor aceptado |
|---|---|
| SHA-256 del adjunto incrustado | `e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3` |
| Carácter usado en el nombre | `U+202E` |
| Host de la etapa descargada | `portal.meridian.thm` |
| PID del intérprete | `1996` |
| Clave del documento transferido | `3c7a8c88466f5b869bea15f333e3be01` |
| SHA-256 del documento recuperado | `c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a` |

### Revisar el nombre y el hash

Para revisar el adjunto hay que trabajar con sus bytes MIME, no fiarse del nombre que muestra el correo. El carácter `U+202E` cambia la dirección de presentación del texto y puede hacer que la extensión aparente resulte engañosa. Mostrar `repr(nombre)` y los puntos de código ayuda a verlo.

Para el PID interesa el evento que crea el intérprete; el padre puede tener otro número. Y el hash final se calcula sobre el documento ya recuperado, no sobre los bytes cifrados de la transferencia.

Este ejemplo sirve para extraer el hash y revisar el nombre de los adjuntos. Es una guía para repetir la comprobación; no conservamos la salida original de este paso:

```python
from email import policy
from email.parser import BytesParser
from pathlib import Path
import hashlib

msg = BytesParser(policy=policy.default).parsebytes(Path('correo.eml').read_bytes())
for part in msg.iter_attachments():
    name = part.get_filename() or ''
    payload = part.get_payload(decode=True)
    print(repr(name), ['U+%04X' % ord(c) for c in name])
    print(hashlib.sha256(payload).hexdigest())
```

Faltan el PCAP y el adjunto original en las notas que conservamos. Por eso dejamos las respuestas verificadas, sin añadir un nombre de intérprete o un modo de cifrado que no podamos contrastar.

![Figura 5. Evidencia conservada de The Waiting Room completado.](evidencias/tryhackme-waiting-room-completado.png)

<a id="reto-06"></a>

## 06. Day-O: de memoria ejecutable a caché descifrada

### Localizar el proceso y extraer la región

Aquí trabajamos con `memory.mem`, de unos 4,1 GB, usando Volatility 3 y los símbolos incluidos. ReviewClient.exe, PID 6260, tenía una región privada `PAGE_EXECUTE_READWRITE` entre `0x8e0000` y `0x8e0fff`. Era la región que había que extraer y comparar con los archivos del proceso.

```bash
cd ~/Desktop/artifacts
mkdir -p /tmp/day
vol -f memory.mem -o /tmp/day windows.malware.malfind --pid 6260 --dump
vol -f memory.mem windows.handles --pid 6260
vol -f memory.mem -o /tmp/day windows.dumpfiles --pid 6260
```

Los handles apuntaban a `review-cover.png` y `review-cache.dat`. Al comparar el volcado con el PNG recuperado, el mismo código aparecía en el offset 28829. La marca IEND estaba en 28821: el payload venía después del último chunk y su CRC. Aquí hubo una corrección durante la resolución: probamos T1027.003, pero la respuesta correcta era `T1027.009`, Embedded Payloads. El offset permitió entender el motivo.

### Leer el comando del shellcode

El shellcode x86 construía un comando apilando inmediatos y restando 0x25 a cada byte. También resolvía WinExec mediante la búsqueda de exportaciones. La respuesta que aceptó la sala fue `kernel32.WinExec`.

Lo reconstruido era un PowerShell con EncodedCommand. Decodificamos el Base64 como UTF-16LE para leerlo. El script usaba AES-CBC con PKCS7 y tomaba los primeros 16 bytes de `review-cache.dat` como IV; el resultado debía ser `review-cache.zip`.

Al descifrar la caché aparecieron `release/approval.txt` y `release/contacts.csv` dentro de un ZIP. La flag estaba en la referencia de aprobación de approval.txt. Aunque el archivo recuperado tenía relleno de páginas al final, zipfile pudo abrirlo.

### Respuestas aceptadas

| Campo | Respuesta |
|---|---|
| Ejecutable | `ReviewClient.exe` |
| Dirección inicial | `0x8e0000` |
| Archivo con el mismo payload | `review-cover.png` |
| Subtécnica | `T1027.009` |
| API | `kernel32.WinExec` |
| Clave hexadecimal | `7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8` |
| Flag | `THM{2b3cc75adab999202e1879af542b2c11}` |

![Figura 6. Captura de la sesión: reto al 100 % y decodificación de la caché en la terminal.](evidencias/day-o-evidencia-100.png)

El script completo está en `scripts/day-o-recuperar.py`. Usa los offsets de este payload y espera los archivos extraídos en `/tmp/day`. Lo ejecutamos con el entorno analysis-python, que tenía Crypto.

### Reconstrucción del comando y lectura del ZIP

Esta es la parte que reconstruye el comando y abre la caché. Se invierte el orden de los inmediatos para recuperar el orden de la pila, se resta 0x25 y se decodifica PowerShell como texto:

```python
import base64, io, zipfile
from Crypto.Cipher import AES

# d contiene el volcado de la región del PID 6260.
b = b''.join([d[i+1:i+5] for i in range(0x8d, 0x529, 5)][::-1])
command = bytes((x - 0x25) % 256 for x in b)
stage = base64.b64decode(command.split()[-1]).decode('utf-16le')
key = base64.b64decode(stage.split("'")[1])
# r contiene review-cache.dat recuperado de memoria.
plain = AES.new(key, AES.MODE_CBC, r[:16]).decrypt(r[16:])
archive = zipfile.ZipFile(io.BytesIO(plain))
print(archive.read('release/approval.txt').decode())
```

<a id="reto-07"></a>

## 07. Strange & Unusual Activity: C2 entre tráfico legítimo

### Los datos en Kibana

La búsqueda cubría el 7 de octubre de 2025 en Kibana. Los índices zeek-dns y zeek-conn tenían 3995 consultas DNS y 5345 conexiones. Comprobamos que los resultados exportados incluían todos los documentos antes de contar.

Había bastante tráfico de comprobaciones de conectividad y telemetría. El dominio que acabó encajando con la actividad del host fue `edge-metrics-sync.net`, que resolvía a `203.0.113.77`.

### Buscar el dominio y las conexiones

Seleccionar la ventana completa del día de captura y filtrar DNS:

```text
query : "edge-metrics-sync.net" and id.orig_h : "10.10.14.160"
```

El filtro devolvió 289 consultas del mismo origen. Entre consultas había unos 300 segundos, con una media de 299,66. Los intervalos variaban ligeramente, pero el patrón de cinco minutos seguía siendo claro.

Después se examinaron las conexiones al destino resuelto:

```text
id.orig_h : "10.10.14.160" and id.resp_h : "203.0.113.77"
```

Ordenando `orig_bytes` de mayor a menor apareció una conexión con 54078822 bytes enviados y 303 recibidos, servicio SSL, TCP/443 y estado SF. Comenzó a las `2025-10-07T15:27:53.766047+00:00` y duró 75,227793 segundos. Su UID es `C1671738666754672`.

### Por qué el conteo aceptado es 289

Este conteo tenía una trampa: en conexiones había 288 pequeñas y una transferencia grande. La pista de la pregunta pedía contar DNS desde el host al dominio C2. Por eso la respuesta era 289; quitar la transferencia grande para responder 288 era contar otra cosa.

Para los bytes enviados usamos `orig_bytes`, que corresponde al iniciador de la conexión. `resp_bytes` era el sentido contrario. Como el tráfico era SSL, estos registros permiten medir la salida, pero no leer qué documentos se enviaron.

| Campo | Respuesta aceptada |
|---|---|
| Dominio C2 | `edge-metrics-sync.net` |
| Intervalo | `300` segundos |
| Host comprometido | `10.10.14.160` |
| Callbacks según el filtro DNS | `289` |
| Mayor transferencia | `54078822` bytes |

![Figura 7. Recorte de la sesión: consulta del conjunto completo y transferencia masiva en Zeek. Se conserva también la captura original.](evidencias/strange-unusual-recorte.png)

### Comprobar el resultado exportado

Con la respuesta JSON de Elasticsearch, esta comprobación da el total y la conexión más grande. Hay que volver a exportar `/tmp/conn.json` desde el laboratorio para repetirla; no está incluido en el repositorio. Las dos aserciones evitan contar solo una página de resultados.

```python
import json
response = json.load(open('/tmp/conn.json'))
hits = response['hits']
assert hits['total']['relation'] == 'eq'
assert len(hits['hits']) == hits['total']['value']
rows = [h['_source'] for h in hits['hits']]
c2 = [r for r in rows if r.get('id.orig_h') == '10.10.14.160'
      and r.get('id.resp_h') == '203.0.113.77']
largest = max(c2, key=lambda r: r['orig_bytes'])
print(len(c2), largest['orig_bytes'], largest['uid'])
# 289 54078822 C1671738666754672
```

<a id="reto-08"></a>

## 08. Dead Endpoint: recuperación del ransomware

### Montar la imagen

El archivo de este reto era `disk.img`, de unos 12 GB. Con mmls vimos que la partición empezaba en el sector 2099200. Multiplicando por 512 obtuvimos el offset 1074790400 para montarla. Usamos `ro,noload` para leerla sin reproducir el journal.

```bash
cd ~/Desktop/artifacts
mmls disk.img
sudo mkdir -p /mnt/dead
sudo mount -o ro,noload,loop,offset=1074790400 disk.img /mnt/dead
```

### Encontrar la entrada del ataque

En `/srv/gallery/app/gallery.py` encontramos el endpoint POST `/api/albums/<int:album_id>/export`. Metía `selection` dentro de un comando tar y lo ejecutaba con `shell=True`. Eso dejaba que el valor se interpretase como parte de un comando de shell.

Copiamos la base SQLite junto con el WAL y el SHM para consultarla aparte. Un detalle de permisos: el comodín tenía que expandirse dentro del `sudo sh -c`, porque el usuario normal no podía recorrer la carpeta de origen.

```bash
mkdir -p /tmp/dead
sudo sh -c 'cp /mnt/dead/srv/gallery/data/gallery.sqlite3* /tmp/dead/'
sudo sqlite3 /tmp/dead/gallery.sqlite3 'select * from exports;'
```

La tabla exports conservó un trabajo del álbum 1 que añadía, después de un punto y coma, una descarga mediante curl, un cambio de permisos y el lanzamiento de `/srv/gallery/.cache/.indexd`. El trabajo fue solicitado a las 05:36:54.547 UTC del 20 de octubre de 2026 y terminó a las 05:36:54.753. Esa evidencia, junto con el código vulnerable, identificó `/api/albums/1/export` como el endpoint abusado.

### Revisar .indexd

```bash
B=/mnt/dead/srv/gallery/.cache/.indexd
sudo sha256sum "$B"
sudo strings "$B" | grep -E 'EVP|AES|RAND|clock|locked|originals'
sudo objdump -d -M intel "$B" > /tmp/index.dis
```

`.indexd` era un ELF x86-64 con SHA-256 `6a0e5b25a919a94952b34e38d8e8b595036d1ef6a026bf5cca38a0d34459102f`. Entre los imports estaba EVP_aes_256_gcm, y las rutas apuntaban a tres JPEG de `/srv/gallery/media/originals`. Lo revisamos con strings y desensamblado, sin ejecutarlo.

### Una clave que dependía de la hora

La rutina consultaba CLOCK_REALTIME y calculaba una semilla como `segundos * 1000 + nanosegundos // 1000000`. Desde ella generaba cuatro salidas de SplitMix64, cada una serializada en little endian, para formar la clave AES de 32 bytes. El nonce de 12 bytes se generaba con RAND_bytes y quedaba en el archivo.

El problema estaba en la semilla temporal. Las marcas de los archivos y la hora del trabajo acotaban cuándo había arrancado el cifrado, así que probamos los milisegundos cercanos. Para aceptar una clave exigimos que GCM validase la etiqueta, no solo que los primeros bytes parecieran un JPEG.

### La cabecera de los archivos .locked

| Offset | Longitud | Contenido |
|---|---|---|
| 0 | 4 | Magic GPH1 |
| 4 | 1 | Versión observada: 1 |
| 8 | 8 | Tamaño original, little endian |
| 16 | 12 | Nonce GCM |
| 28 | 16 | Etiqueta de autenticación |
| 44 | 4 | Relleno / campo no usado por el descifrado reproducido |
| 48 | Resto | Texto cifrado |

Los primeros 28 bytes se usan como AAD. La API AESGCM de cryptography recibe el texto cifrado seguido de la etiqueta; por ello se reconstruye `datos[48:] + datos[28:44]`, con nonce `datos[16:28]` y AAD `datos[:28]`.

```python
plain = AESGCM(key(seed)).decrypt(
    data[16:28], data[48:] + data[28:44], data[:28]
)
```

La semilla que funcionó fue `1792474614662`. Pasó la autenticación GCM en las tres imágenes y devolvió los tamaños esperados: yard_0147.jpg, 278610 bytes; yard_0148.jpg, 418140 bytes; yard_0152.jpg, 180683 bytes. En yard_0152.jpg estaba el checklist con la flag al pie.

![Figura 8. Checklist recuperado de yard_0152.jpg; la flag aparece al pie. Captura original de la sesión.](evidencias/dead-endpoint-checklist-recuperado.png)

### Respuestas aceptadas

| Campo | Respuesta |
|---|---|
| Endpoint | `/api/albums/1/export` |
| Ejecutable | `/srv/gallery/.cache/.indexd` |
| SHA-256 | `6a0e5b25a919a94952b34e38d8e8b595036d1ef6a026bf5cca38a0d34459102f` |
| Algoritmo y modo | `AES-256-GCM` |
| Semilla | `1792474614662` |
| Flag | `THM{R4ns0mw4r3_K3ys_Ar3_A_M4tt3r_0f_T1m3}` |

### Recuperar las imágenes

Dejamos el descifrador en `scripts/dead-endpoint-recuperar.py`. Incluye SplitMix64, comprueba la etiqueta GCM y verifica el tamaño original. Guarda copias en otra carpeta y falla si el archivo de salida ya existe.

```bash
sudo python3 scripts/dead-endpoint-recuperar.py \
  /mnt/dead/srv/gallery/media/originals /tmp/recuperadas
```

![Figura 9. Confirmación de Dead Endpoint completado.](evidencias/dead-endpoint-completado.png)

<a id="reto-09"></a>

## 09. Notas finales

Dos detalles hicieron cambiar respuestas durante la resolución: en Day-O, encontrar el código después de IEND aclaró la subtécnica MITRE; en el reto de red, leer la pista del conteo DNS resolvió la diferencia entre 288 y 289. En Dead Endpoint, la comprobación decisiva fue que GCM validase los tres archivos con la misma semilla.

Quedan huecos en las notas: las nueve alertas del SOC no están documentadas una por una, el tabletop conserva el cierre y de Waiting Room faltan pasos de extracción. Las respuestas y capturas disponibles están en sus apartados. En Quiet As The Grave, el comando de subida sí quedó registrado, pero no la recepción del ZIP en el C2.

### Enlaces

- Página del evento y títulos oficiales: https://tryhackme.com/downtime
- Repossessed: https://tryhackme.com/soc-sim/scenarios?scenario=repossessed
- Quiet As The Grave: https://tryhackme.com/threat-hunting-sim/scenarios?scenario=quiet-as-the-grave
- Tabletop del evento: https://tryhackme.com/tabletop-exercises/exercises?exercise=6ad661d34d8777bc630645b5
- Handbook: https://tryhackme.com/room/handbookfortherecentlycompromised
- The Waiting Room: https://tryhackme.com/room/thewaitingroom
- Day-O: https://tryhackme.com/room/dayo
- Strange & Unusual Activity: https://tryhackme.com/room/strangeunusualactivity
- Dead Endpoint: https://tryhackme.com/room/deadendpoint
- Embedded Payloads: https://attack.mitre.org/techniques/T1027/009/

Las salas pueden pedir inicio de sesión. Los nombres del evento y las respuestas de Handbook y The Waiting Room se comprobaron de nuevo al preparar el writeup.

### Archivos del repositorio

El texto actualizado está en `README.md`. `WRITEUP.pdf` conserva la primera versión del informe. Las capturas están en evidencias y los descifradores en scripts. Los logs crudos y las etapas completas de la investigación quedaron en el paquete local. `MANIFEST.sha256` recoge los hashes de los archivos publicados.