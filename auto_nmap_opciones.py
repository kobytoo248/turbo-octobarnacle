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

if __name__ == "__main__":
    usar_proxychains = input("¿Quieres usar proxychains y Tor para el escaneo? (s/n): ").lower() == "s"
    objetivo = input("Introduce la IP, dominio o IPv6 objetivo: ")
    if not validar_objetivo(objetivo):
        print("Objetivo inválido. Introduce una IP, dominio o IPv6 válido.")
        exit(1)

    mostrar_ayuda()
    opcion = input("Elige una opción (1-14, h para ayuda): ")
    extra = input("¿Quieres añadir parámetros extra a Nmap? (deja vacío si no): ")

    # ...resto del menú...