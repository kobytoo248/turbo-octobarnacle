# Automatizaciones de Pentesting

Herramienta en Python para automatizar escaneos y tareas comunes de pentesting usando Nmap, Hydra, Gobuster, FFUF, Wfuzz, Searchsploit, Netcat, Metasploit, John the Ripper, Hashcat y Aircrack-ng.

## Características

- Escaneo de puertos y servicios con Nmap (varios modos y formatos)
- Detección de vulnerabilidades con scripts NSE y Nikto
- Fuerza bruta de contraseñas con Hydra
- Fuzzing de directorios y archivos con Gobuster, FFUF y Wfuzz
- Generación de payloads con msfvenom
- Búsqueda de exploits locales con Searchsploit
- Comandos útiles de Netcat
- Automatización de Metasploit con archivos `.rc`
- Cracking de hashes con John the Ripper y Hashcat
- Cracking de WiFi WPA/WPA2 con Aircrack-ng
- Integración con herramientas como Enum4linux, Dirsearch, Nessus, OpenVAS, WhatWeb, etc.
- Validación de diccionarios y URLs para evitar errores comunes
- Menú interactivo en bucle para ejecutar varias opciones sin reiniciar el script

## Requisitos

- Python 3.x
- Las herramientas externas instaladas en el sistema (`nmap`, `hydra`, `gobuster`, `ffuf`, `wfuzz`, `searchsploit`, `netcat`, `msfvenom`, `msfconsole`, `john`, `hashcat`, `aircrack-ng`, etc.)

## Uso

```bash
python3 auto_nmap_opciones.py
```

Sigue el menú interactivo y selecciona la opción deseada.  
Para salir, escribe `q` en el menú.

## Ejemplo de opciones

- **Escaneo básico:**  
  Escanea puertos abiertos rápidamente.
- **Fuzzing con FFUF y Wfuzz:**  
  Busca archivos y directorios ocultos en aplicaciones web.
- **Searchsploit:**  
  Busca exploits locales para un servicio o versión específica y guarda los resultados en un archivo.
- **Netcat:**  
  Consulta comandos útiles para transferencia de archivos y shells reversas.
- **Metasploit:**  
  Ejecuta msfconsole con un archivo `.rc` para automatizar exploits y payloads.
- **John the Ripper:**  
  Crackea hashes usando diccionarios personalizados.
- **Hashcat:**  
  Crackea hashes con soporte para múltiples algoritmos y modos.
- **Aircrack-ng:**  
  Crackea contraseñas WPA/WPA2 de redes WiFi usando archivos de captura y diccionarios.

## Notas

- Para usar proxychains y Tor, selecciona la opción al inicio.
- Los resultados de Searchsploit se guardan automáticamente en archivos de texto.
- Revisa la ayuda integrada (`h`) para ver todas las opciones disponibles.
- Puedes ejecutar varias opciones sin reiniciar el script.

## Licencia

MIT
