# Dossier del evento It's Downtime! - TryHackMe

Autoría: Nighmar3 · CiberSecUNI.

El dossier cubre ocho retos. `WRITEUP.pdf` contiene la versión maquetada con marcadores de navegación; `README.md` es la versión editable.

## Archivos

- `evidencias/`: capturas originales y recortes identificados en el texto. Las imágenes muestran resultados y fragmentos de la sesión; no son ilustraciones generadas.
- `scripts/day-o-recuperar.py`: reconstrucción estática del comando y descifrado de la caché. Requiere Python 3, PyCryptodome (`Crypto`) y los archivos extraídos por Volatility en `/tmp/day`. Los offsets y patrones de nombre corresponden a este reto.
- `scripts/dead-endpoint-recuperar.py`: derivación de la clave y recuperación de los archivos `.locked`. Requiere Python 3 y `cryptography`; recibe carpetas de origen y destino. Valida GCM y el tamaño original y escribe copias sin sobrescribir destinos existentes.
- `MANIFEST.sha256`: hashes de integridad del paquete, excluyendo el propio manifiesto.

Las imágenes completas de memoria/disco, los EVTX originales y los PCAP no se incluyen. Para reproducir los análisis se necesitan los artefactos del laboratorio correspondiente. Las limitaciones de la evidencia conservada se explican en cada capítulo.

## Verificar la integridad

Desde esta carpeta, en Linux:

```bash
sha256sum -c MANIFEST.sha256
```

Desde esta carpeta, en PowerShell:

```powershell
Get-Content MANIFEST.sha256 | ForEach-Object {
    $expected, $relative = $_ -split '  ', 2
    $actual = (Get-FileHash -LiteralPath $relative -Algorithm SHA256).Hash
    if ($actual.ToLowerInvariant() -ne $expected) { throw "Hash distinto: $relative" }
}
```

Los comandos y scripts de recuperación leen evidencia y descifran copias; no invocan el malware.

La publicación en GitHub omite los logs crudos y las etapas completas de investigación. Las referencias del PDF a fuentes corresponden al paquete local original.
