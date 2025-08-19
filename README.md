# Automatización de Escaneos y Pentesting

Este script permite automatizar escaneos y pruebas de seguridad usando herramientas como Nmap, Dirsearch, Hydra, Gobuster, Nessus y msfvenom.

## Características

- Escaneo de puertos y servicios con Nmap
- Detección de sistema operativo y vulnerabilidades
- Exportación de resultados en XML y JSON
- Fuerza bruta de servicios (FTP, SSH, MySQL, HTTP, SMB, etc.) con Hydra
- Descubrimiento de directorios y archivos con Dirsearch y Gobuster
- Escaneo de vulnerabilidades con Nessus (manual o por API/CLI)
- Generación de payloads con msfvenom (Windows, Linux, Android, Mac, etc.)
- Soporte para proxychains y Tor
- Menú interactivo y fácil de usar

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
...
19. Generar payloads con msfvenom (Windows, Linux, Android, Mac, etc.)
h. Mostrar esta ayuda
```

## Personalización

Puedes agregar más herramientas o modificar los comandos en el script para adaptarlo a tus necesidades.

## Créditos

Script desarrollado por [Tu Nombre o Usuario de GitHub].

---

**¡Automatiza tus escaneos y pentesting de forma sencilla!**
