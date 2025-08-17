import subprocess
import re
import time

def validar_objetivo(objetivo):
    ip_regex = r"^\d{1,3}(\.\d{1,3}){3}$"
    dominio_regex = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    ipv6_regex = r"^([0-9a-fA-F:]+)$"
    if re.match(ip_regex, objetivo) or re.match(dominio_regex, objetivo) or re.match(ipv6_regex, objetivo):
        return True
    return False

def ejecutar_comando(comando):
    print(f"\nEjecutando: {' '.join(comando)}")
    inicio = time.time()
    try:
        subprocess.run(comando, check=True)
        print(f"Escaneo completado en {round(time.time() - inicio, 2)} segundos.")
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Nmap: {e}")
    except FileNotFoundError:
        print("Nmap no está instalado o no se encuentra en el PATH.")

def escaneo_basico(target, min_rate, extra=""):
    comando = [
        "nmap", "-p-", "--open", "--min-rate", str(min_rate),
        "-Pn", "-n", "-vvv", target, "-oN", "nmap_result.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_servicios(target, extra=""):
    comando = [
        "nmap", "-sV", "-Pn", "-n", "-vvv", target, "-oN", "nmap_servicios.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_os(target, extra=""):
    comando = [
        "nmap", "-O", "-Pn", "-n", "-vvv", target, "-oN", "nmap_os.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_xml(target, extra=""):
    comando = [
        "nmap", "-p-", "--open", "-Pn", "-n", "-vvv", target, "-oX", "nmap_result.xml"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_json(target, extra=""):
    comando = [
        "nmap", "-p-", "--open", "-Pn", "-n", "-vvv", target, "-oJ", "nmap_result.json"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_servicios_C(target, extra=""):
    comando = [
        "nmap", "-sV", "-C", "-Pn", "-n", "-vvv", target, "-oN", "nmap_svC.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_agresivo(target, extra=""):
    comando = [
        "nmap", "-A", "-Pn", "-n", "-vvv", target, "-oN", "nmap_agresivo.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_syn(target, extra=""):
    comando = [
        "nmap", "-sS", "-Pn", "-n", "-vvv", target, "-oN", "nmap_syn.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_sigiloso(target, nivel, extra=""):
    comando = [
        "nmap", "-sS", "-T" + str(nivel), "-Pn", "-n", "-vvv", target, "-oN", f"nmap_sigiloso_T{nivel}.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_ipv6(target, extra=""):
    comando = [
        "nmap", "-6", "-Pn", "-n", "-vvv", target, "-oN", "nmap_ipv6.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_nse_vuln(target, extra=""):
    comando = [
        "nmap", "--script", "vuln", "-Pn", "-n", "-vvv", target, "-oN", "nmap_vuln.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_arp(target, extra=""):
    comando = [
        "nmap", "-PR", "-n", "-vvv", target, "-oN", "nmap_arp.txt"
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def ayuda_android():
    print("""
Para usar Nmap en Android (Termux):
1. Instala Termux desde Google Play o F-Droid.
2. Instala Nmap con: pkg install nmap
3. Ejecuta los mismos comandos que en Linux.
Ejemplo: nmap -sV 192.168.1.1
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
h. Mostrar esta ayuda
""")

if __name__ == "__main__":
    objetivo = input("Introduce la IP, dominio o IPv6 objetivo: ")
    if not validar_objetivo(objetivo):
        print("Objetivo inválido. Introduce una IP, dominio o IPv6 válido.")
        exit(1)

    mostrar_ayuda()
    opcion = input("Elige una opción (1-13, h para ayuda): ")
    extra = input("¿Quieres añadir parámetros extra a Nmap? (deja vacío si no): ")

    if opcion == "1":
        while True:
            min_rate = input("Introduce el valor de --min-rate (ejemplo: 200 o 5000): ")
            if min_rate.isdigit() and int(min_rate) > 0:
                min_rate = int(min_rate)
                break
            else:
                print("Por favor, introduce un número entero positivo.")
        escaneo_basico(objetivo, min_rate, extra)
    elif opcion == "2":
        escaneo_servicios(objetivo, extra)
    elif opcion == "3":
        escaneo_os(objetivo, extra)
    elif opcion == "4":
        escaneo_xml(objetivo, extra)
    elif opcion == "5":
        escaneo_json(objetivo, extra)
    elif opcion == "6":
        escaneo_servicios_C(objetivo, extra)
    elif opcion == "7":
        escaneo_agresivo(objetivo, extra)
    elif opcion == "8":
        escaneo_syn(objetivo, extra)
    elif opcion == "9":
        for nivel in range(1, 5):
            escaneo_sigiloso(objetivo, nivel, extra)
    elif opcion == "10":
        escaneo_ipv6(objetivo, extra)
    elif opcion == "11":
        escaneo_nse_vuln(objetivo, extra)
    elif opcion == "12":
        escaneo_arp(objetivo, extra)
    elif opcion == "13":
        ayuda_android()
    elif opcion.lower() == "h":
        mostrar_ayuda()
    else:
        print("Opción no válida.")