# Automatizaciones de Pentesting y OSINT

Herramienta en Python para automatizar escaneos y tareas comunes de pentesting y OSINT usando Nmap, Hydra, Gobuster, FFUF, Wfuzz, Searchsploit, Netcat, Metasploit, John the Ripper, Hashcat, Aircrack-ng, amass, sublist3r, dnsenum, theHarvester, netdiscover, nuclei, cewl, medusa, rustscan, impacket, wpscan, joomscan, xsser, Recon-ng, SpiderFoot, Shodan, Maltego, GHunt, Social Analyzer, Censys, ExifTool y más.

## Características

- Escaneo de puertos y servicios con Nmap (varios modos y formatos)
- Detección de vulnerabilidades con scripts NSE, Nikto y Nuclei
- Fuerza bruta de contraseñas con Hydra y Medusa
- Fuzzing de directorios y archivos con Gobuster, FFUF, Dirsearch y Wfuzz
- Generación de payloads con msfvenom
- Búsqueda de exploits locales con Searchsploit
- Comandos útiles de Netcat
- Automatización de Metasploit con archivos `.rc`
- Cracking de hashes con John the Ripper y Hashcat
- Cracking de WiFi WPA/WPA2 con Aircrack-ng
- Enumeración de subdominios y DNS con amass, sublist3r y dnsenum
- Recolección de correos y dominios con theHarvester
- Descubrimiento de hosts en red local con netdiscover
- Generador de diccionarios personalizados con cewl
- Escaneo de vulnerabilidades en WordPress y Joomla con wpscan y joomscan
- Detección de XSS con xsser
- Automatización de Recon-ng, SpiderFoot, Shodan, Maltego, GHunt, Social Analyzer y Censys para OSINT
- Extracción de metadatos con ExifTool (alternativa a FOCA)
- Validación de rutas, dominios y archivos para evitar errores comunes
- Menú interactivo en bucle para ejecutar varias opciones sin reiniciar el script

## Requisitos

- Python 3.x
- Las herramientas externas instaladas en el sistema (`nmap`, `hydra`, `gobuster`, `ffuf`, `wfuzz`, `searchsploit`, `netcat`, `msfvenom`, `msfconsole`, `john`, `hashcat`, `aircrack-ng`, `amass`, `sublist3r`, `dnsenum`, `theHarvester`, `netdiscover`, `nuclei`, `cewl`, `medusa`, `rustscan`, `impacket-scripts`, `wpscan`, `joomscan`, `xsser`, `recon-ng`, `spiderfoot`, `shodan`, `maltego`, `GHunt`, `social-analyzer`, `censys`, `exiftool`, etc.)

## Uso

```bash
python3 auto_nmap_opciones.py
```

Sigue el menú interactivo y selecciona la opción deseada.  
Para salir, escribe `q` en el menú.

## Opciones principales

1. Escaneo básico de puertos
2. Escaneo de servicios y versiones
...
47. Automatización de Recon-ng (ejecutar scripts .rc en workspace)
48. Recolección OSINT automatizada con SpiderFoot
49. Búsqueda OSINT en dispositivos con Shodan
50. Lanzar Maltego para investigaciones OSINT gráficas
51. Recolección OSINT sobre cuentas Google con GHunt
52. Búsqueda OSINT de perfiles en redes sociales con Social Analyzer
53. Búsqueda OSINT en hosts con Censys
54. Extracción de metadatos de archivos con ExifTool (alternativa a FOCA)

## Ejemplo de uso

- **John the Ripper:**  
  Selecciona la opción 31 y proporciona el archivo de hashes y el diccionario.
- **Hashcat:**  
  Selecciona la opción 32, indica el archivo de hashes, el diccionario y el modo.
- **Aircrack-ng:**  
  Selecciona la opción 33, indica el archivo .cap y el diccionario.
- **amass/sublist3r/dnsenum/theHarvester:**  
  Ingresa un dominio válido (ejemplo.com) y sigue las instrucciones.
- **wpscan/joomscan/xsser:**  
  Ingresa la URL del sitio web objetivo.
- **ExifTool:**  
  Ingresa la ruta al archivo (imagen, PDF, DOC, etc.) para extraer metadatos.

## Notas

- Para usar proxychains y Tor, selecciona la opción al inicio.
- Los resultados de Searchsploit y otros escaneos se pueden guardar automáticamente en archivos de texto.
- Revisa la ayuda integrada (`h`) para ver todas las opciones disponibles.
- Puedes ejecutar varias opciones sin reiniciar el script.
- La opción de Censys requiere un Personal Access Token (API Key).

## Licencia

MIT

---

¿Quieres agregar ejemplos de uso para alguna opción específica o personalizar alguna
