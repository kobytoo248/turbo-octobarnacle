# ...existing code...

def escaneo_nmap_msf(target, extra=""):
    xml_file = "nmap_result.xml"
    comando_nmap = [
        "nmap", "-p-", "--open", "-Pn", "-n", "-vvv", target, "-oX", xml_file
    ]
    if extra:
        comando_nmap += extra.split()
    ejecutar_comando(comando_nmap)

    print("\nImportando resultados en Metasploit...")
    comando_msf = f"msfconsole -q -x 'db_import {xml_file}; hosts; services; exit'"
    try:
        subprocess.run(comando_msf, shell=True, check=True)
        print("Importación a Metasploit completada.")
    except subprocess.CalledProcessError as e:
        print(f"Error al importar en Metasploit: {e}")

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

# ...existing code...

if __name__ == "__main__":
    objetivo = input("Introduce la IP, dominio o IPv6 objetivo: ")
    if not validar_objetivo(objetivo):
        print("Objetivo inválido. Introduce una IP, dominio o IPv6 válido.")
        exit(1)

    mostrar_ayuda()
    opcion = input("Elige una opción (1-14, h para ayuda): ")
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
    elif opcion == "14":
        escaneo_nmap_msf(objetivo, extra)
    elif opcion.lower() == "h":
        mostrar_ayuda()
    else:
        print("Opción no válida.")