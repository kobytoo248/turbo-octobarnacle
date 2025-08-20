# Automatización de Escaneos y Pentesting

Este script permite automatizar escaneos y pruebas de seguridad usando herramientas como Nmap, Dirsearch, Hydra, Gobuster, Nessus y msfvenom.

## Características

- Escaneo de puertos y servicios con Nmap (TCP, UDP, IPv6)
- Detección de sistema operativo y vulnerabilidades
- Exportación de resultados en XML, JSON y TXT
- Ejecución de scripts NSE personalizados
- Fuerza bruta de servicios (FTP, SSH, MySQL, HTTP, SMB, etc.) con Hydra
- Descubrimiento de directorios y archivos con Dirsearch y Gobuster
- Escaneo de vulnerabilidades con Nessus (manual o por API/CLI)
- Generación de payloads con msfvenom (Windows, Linux, Android, Mac, etc.)
- Soporte para proxychains y Tor
- Menú interactivo y fácil de usar
- Resumen automático de servicios encontrados tras cada escaneo

## Requisitos

- Python 3
- Nmap
- Dirsearch
- Hydra
- Gobuster
- Nessus (opcional)
- msfvenom (Metasploit Framework)
- proxychains (opcional)
- Diccionarios de contraseñas y directorios (por ejemplo, rockyou.txt, common.txt)

## Uso

1. Clona el repositorio y accede a la carpeta del script.
2. Ejecuta el script:
    ```bash
    python3 auto_nmap_opciones.py
    ```
3. Sigue las instrucciones del menú para elegir el tipo de escaneo o ataque.

## Ejemplo de menú

```
Opciones de escaneo:
1. Escaneo básico (puertos, --open, --min-rate)
2. Escaneo de servicios y versiones (-sV)
3. Detección de sistema operativo (-O)
4. Guardar resultado en XML
5. Guardar resultado en JSON
6. Escaneo de servicios con -sV --script=default
7. Escaneo agresivo (-A)
8. Escaneo SYN sigiloso (-sS)
9. Escaneos sigilosos con T1, T2, T3, T4
10. Escaneo IPv6
11. Escaneo de vulnerabilidades con NSE (--script vuln)
12. Escaneo ARP para MACs (-PR)
13. Ayuda para Nmap en Android
14. Escaneo Nmap y carga en Metasploit (db_import)
15. Escaneo de directorios con Dirsearch
16. Fuerza bruta con Hydra (FTP, SSH, MySQL)
17. Escaneo de directorios y archivos con Gobuster
18. Escaneo de vulnerabilidades con Nessus
19. Generar payloads con msfvenom (Windows, Linux, Android, Mac, etc.)
20. Escaneo con script NSE personalizado
21. Escaneo UDP (-sU)
h. Mostrar esta ayuda
```

## Personalización

Puedes agregar más herramientas o modificar los comandos en el script para adaptarlo a tus necesidades.

## Créditos

Script desarrollado por [Tu Nombre o Usuario de GitHub].

---

**¡Automatiza tus escaneos y pentesting de forma sencilla!**
