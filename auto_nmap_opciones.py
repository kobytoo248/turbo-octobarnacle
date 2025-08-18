import re
import subprocess
import time

def validar_objetivo(objetivo):
    ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
    dominio_regex = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    ipv6_regex = r"^([0-9a-fA-F:]+)$"
    if re.match(ip_regex, objetivo) or re.match(dominio_regex, objetivo) or re.match(ipv6_regex, objetivo):
        return True
    return False

# ...resto de tus funciones...

def ejecutar_comando(comando):
    if usar_proxychains:
        comando = ["proxychains"] + comando
    print(f"\nEjecutando: {' '.join(comando)}")
    inicio = time.time()
    try:
        subprocess.run(comando, check=True)
        print(f"Escaneo completado en {round(time.time() - inicio, 2)} segundos.")
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Nmap: {e}")
    except FileNotFoundError:
        print("Nmap no está instalado o no se encuentra en el PATH.")

# ...resto del código...
    extra = input("¿Quieres añadir parámetros extra a Nmap? (deja vacío si no): ")
    if extra.lower() in ["si", "no"]:
        extra = ""
    # ...resto del menú...
    print("""
Opciones de escaneo:
1. Escaneo básico (puertos, --open, --min-rate)
2. Escaneo de servicios y versiones (-sV)
3. Detección de sistema operativo (-O)
4. Guardar resultado en XML
5. Guardar resultado en JSON
6. Escaneo de servicios con -sV -C
7. Escaneo agresivo (-A)
8. Escaneo SYN sigiloso (-sS)
9. Escaneos sigilosos con T1, T2, T3, T4
10. Escaneo IPv6
11. Escaneo de vulnerabilidades con NSE (--script vuln)
12. Escaneo ARP para MACs (-PR)
13. Ayuda para Nmap en Android
14. Escaneo Nmap y carga en Metasploit (db_import)
h. Mostrar esta ayuda
""")

def mostrar_ayuda():
    print("""
Opciones de escaneo:
1. Escaneo básico (puertos, --open, --min-rate)
2. Escaneo de servicios y versiones (-sV)
3. Detección de sistema operativo (-O)
4. Guardar resultado en XML
5. Guardar resultado en JSON
6. Escaneo de servicios con -sV -C
7. Escaneo agresivo (-A)
8. Escaneo SYN sigiloso (-sS)
9. Escaneos sigilosos con T1, T2, T3, T4
10. Escaneo IPv6
11. Escaneo de vulnerabilidades con NSE (--script vuln)
12. Escaneo ARP para MACs (-PR)
13. Ayuda para Nmap en Android
14. Escaneo Nmap y carga en Metasploit (db_import)
h. Mostrar esta ayuda
""")

if __name__ == "__main__":
    usar_proxychains = input("¿Quieres usar proxychains y Tor para el escaneo? (s/n): ").lower() == "s"
    objetivo = input("Introduce la IP, dominio o IPv6 objetivo: ")
    if not validar_objetivo(objetivo):
        print("Objetivo inválido. Introduce una IP, dominio o IPv6 válido.")
        exit(1)

    mostrar_ayuda()
    opcion = input("Elige una opción (1-14, h para ayuda): ")
    extra = input("¿Quieres añadir parámetros extra a Nmap? (deja vacío si no): ")
    if extra.lower() in ["si", "no"]:
        extra = ""

    # ...resto del menú y lógica...