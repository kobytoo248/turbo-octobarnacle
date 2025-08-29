# Automatizaciones de Pentesting y OSINT

Herramienta en Python para automatizar escaneos y tareas comunes de pentesting y OSINT usando Nmap, Hydra, Gobuster, FFUF, Wfuzz, Searchsploit, Netcat, Metasploit, John the Ripper, Hashcat, Aircrack-ng, amass, sublist3r, dnsenum, theHarvester, netdiscover, nuclei, cewl, medusa, rustscan, impacket, wpscan, joomscan, xsser, Recon-ng, SpiderFoot, Shodan, Maltego, GHunt, Social Analyzer, Censys, ExifTool, sqlmap, Sherlock, Subfinder, CrackMapExec, Binwalk y más.

## Características

- Menú interactivo con más de 59 opciones de pentesting y OSINT.
- Validación de rutas, dominios y archivos para evitar errores comunes.
- Automatización de escaneos, fuerza bruta, fuzzing, recolección OSINT y análisis de vulnerabilidades.
- Integración de herramientas avanzadas para redes Windows/AD y análisis de binarios.
- Resultados guardados automáticamente en archivos para cada herramienta.

## Requisitos

- Python 3.x
- Las herramientas externas instaladas en el sistema (`nmap`, `hydra`, `gobuster`, `ffuf`, `wfuzz`, `searchsploit`, `netcat`, `msfvenom`, `msfconsole`, `john`, `hashcat`, `aircrack-ng`, `amass`, `sublist3r`, `dnsenum`, `theHarvester`, `netdiscover`, `nuclei`, `cewl`, `medusa`, `rustscan`, `impacket-scripts`, `wpscan`, `joomscan`, `xsser`, `recon-ng`, `spiderfoot`, `shodan`, `maltego`, `GHunt`, `social-analyzer`, `censys`, `exiftool`, `sqlmap`, `sherlock`, `subfinder`, `crackmapexec`, `binwalk`, etc.)

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
55. Automatización de SQL Injection con sqlmap
56. Búsqueda de usuarios en redes sociales con Sherlock
57. Enumeración de subdominios con Subfinder
58. Automatización de ataques SMB/AD con CrackMapExec
59. Análisis de archivos binarios y firmware con Binwalk

## Ejemplo de uso

- **Sherlock:**  
  Selecciona la opción 56 y proporciona el nombre de usuario a buscar.
- **Subfinder:**  
  Selecciona la opción 57 e ingresa el dominio objetivo.
- **CrackMapExec:**  
  Selecciona la opción 58 e ingresa IP/rango, usuario, contraseña y dominio.
- **Binwalk:**  
  Selecciona la opción 59 e ingresa la ruta al archivo binario/firmware.

## Notas

- Para usar proxychains y Tor, selecciona la opción al inicio.
- Los resultados de cada herramienta se guardan automáticamente en archivos de texto.
- Revisa la ayuda integrada (`h`) para ver todas las opciones disponibles.
- Puedes ejecutar varias opciones sin reiniciar el script.
- Algunas herramientas requieren configuración adicional (API keys, tokens, etc.).

## Licencia

MIT

---

¿Quieres agregar ejemplos de uso para alguna opción específica o personalizar alguna
