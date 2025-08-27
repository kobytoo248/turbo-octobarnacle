# Automatizaciones de Pentesting

Herramienta en Python para automatizar escaneos y tareas comunes de pentesting usando Nmap, Hydra, Gobuster, FFUF, Wfuzz, Searchsploit, Netcat, Metasploit, John the Ripper, Hashcat, Aircrack-ng, amass, sublist3r, dnsenum, theHarvester, netdiscover, nuclei, cewl, medusa, rustscan, impacket, wpscan, joomscan, xsser y más.

## Características

- Escaneo de puertos y servicios con Nmap (varios modos y formatos)
- Detección de vulnerabilidades con scripts NSE y Nikto
- Fuerza bruta de contraseñas con Hydra y Medusa
- Fuzzing de directorios y archivos con Gobuster, FFUF y Wfuzz
- Generación de payloads con msfvenom
- Búsqueda de exploits locales con Searchsploit
- Comandos útiles de Netcat
- Automatización de Metasploit con archivos `.rc`
- Cracking de hashes con John the Ripper y Hashcat
- Cracking de WiFi WPA/WPA2 con Aircrack-ng
- Enumeración de subdominios con amass y sublist3r
- Enumeración DNS con dnsenum
- Recolección de correos y dominios con theHarvester
- Descubrimiento de hosts en red local con netdiscover
- Escaneo de vulnerabilidades con nuclei
- Generador de diccionarios personalizados con cewl
- Fuerza bruta de servicios con medusa
- Escaneo de puertos rápido con rustscan
- Ataques Kerberos AS-REP roasting con impacket (GetNPUsers.py)
- Escaneo de vulnerabilidades en WordPress con wpscan
- Escaneo de vulnerabilidades en Joomla con joomscan
- Detección de XSS en aplicaciones web con xsser
- Validación de diccionarios y URLs para evitar errores comunes
- Menú interactivo en bucle para ejecutar varias opciones sin reiniciar el script

## Requisitos

- Python 3.x
- Las herramientas externas instaladas en el sistema (`nmap`, `hydra`, `gobuster`, `ffuf`, `wfuzz`, `searchsploit`, `netcat`, `msfvenom`, `msfconsole`, `john`, `hashcat`, `aircrack-ng`, `amass`, `sublist3r`, `dnsenum`, `theHarvester`, `netdiscover`, `nuclei`, `cewl`, `medusa`, `rustscan`, `impacket-scripts`, `wpscan`, `joomscan`, `xsser`, etc.)

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
31. Cracking de hashes con John the Ripper
32. Cracking de hashes con Hashcat
33. Cracking de WiFi WPA/WPA2 con Aircrack-ng
34. Enumeración de subdominios con amass
35. Enumeración de subdominios con sublist3r
36. Enumeración DNS con dnsenum
37. Recolección de correos y dominios con theHarvester
38. Descubrimiento de hosts en red local con netdiscover
39. Escaneo de vulnerabilidades con nuclei
40. Generador de diccionarios personalizados con cewl
41. Fuerza bruta de servicios con medusa
42. Escaneo de puertos rápido con rustscan
43. Ataques Kerberos AS-REP roasting con impacket (GetNPUsers.py)
44. Escaneo de vulnerabilidades en WordPress con wpscan
45. Escaneo de vulnerabilidades en Joomla con joomscan
46. Detección de XSS en aplicaciones web con xsser

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

## Notas

- Para usar proxychains y Tor, selecciona la opción al inicio.
- Los resultados de Searchsploit y otros escaneos se pueden guardar automáticamente en archivos de texto.
- Revisa la ayuda integrada (`h`) para ver todas las opciones disponibles.
- Puedes ejecutar varias opciones sin reiniciar el script.

## Licencia

MIT

---

¿Quieres agregar ejemplos de uso para alguna opción específica o
