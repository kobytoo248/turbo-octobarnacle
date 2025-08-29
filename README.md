# Automatizaciones de Pentesting y OSINT

Herramienta en Python para automatizar escaneos y tareas comunes de pentesting y OSINT usando Nmap, Hydra, Gobuster, FFUF, Wfuzz, Searchsploit, Netcat, Metasploit, John the Ripper, Hashcat, Aircrack-ng, amass, sublist3r, dnsenum, theHarvester, netdiscover, nuclei, cewl, medusa, rustscan, impacket, wpscan, joomscan, xsser, Recon-ng, SpiderFoot, Shodan, Maltego, GHunt, Social Analyzer, Censys, ExifTool, sqlmap, Sherlock, Subfinder, CrackMapExec, Binwalk y más.

## Características

- Menú interactivo con más de 59 opciones de pentesting y OSINT.
- Modularización: funciones auxiliares en `utilidades.py`, funciones de escaneo en `herramientas.py`, menú principal en `auto_nmap_opciones.py`.
- Validación de rutas, dominios y archivos para evitar errores comunes.
- Visualización automática de resultados tras cada escaneo.
- Resultados guardados automáticamente en archivos para cada herramienta.
- Mensaje de despedida al salir del menú.

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
  Selecciona la opción 56 y proporciona el nombre de usuario a buscar. El resultado se mostrará automáticamente.
- **Subfinder:**  
  Selecciona la opción 57 e ingresa el dominio objetivo. El resultado se mostrará automáticamente.
- **CrackMapExec:**  
  Selecciona la opción 58 e ingresa IP/rango, usuario, contraseña y dominio.
- **Binwalk:**  
  Selecciona la opción 59 e ingresa la ruta al archivo binario/firmware. El resultado se mostrará automáticamente.

## Notas

- Para usar proxychains y Tor, selecciona la opción al inicio.
- Los resultados de cada herramienta se guardan automáticamente en archivos de texto y se muestran en pantalla.
- Revisa la ayuda integrada (`h`) para ver todas las opciones disponibles.
- Puedes ejecutar varias opciones sin reiniciar el script.
- Algunas herramientas requieren configuración adicional (API keys, tokens, etc.).

## Estructura del proyecto

- `auto_nmap_opciones.py`: menú principal y bucle.
- `herramientas.py`: funciones de escaneo y automatización.
- `utilidades.py`: validaciones y funciones auxiliares.

## Licencia

MIT

---

¿Quieres agregar ejemplos de uso para alguna opción específica, personalizar alguna sección, o incluir capturas de pantalla?
