import subprocess

def escaneo_basico(target, min_rate):
    comando = [
        "nmap", "-p-", "--open", "--min-rate", str(min_rate),
        "-Pn", "-n", "-vvv", target, "-oN", "nmap_result.txt"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

def escaneo_servicios(target):
    comando = [
        "nmap", "-sV", "-Pn", "-n", "-vvv", target, "-oN", "nmap_servicios.txt"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

def escaneo_os(target):
    comando = [
        "nmap", "-O", "-Pn", "-n", "-vvv", target, "-oN", "nmap_os.txt"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

def escaneo_xml(target):
    comando = [
        "nmap", "-p-", "--open", "-Pn", "-n", "-vvv", target, "-oX", "nmap_result.xml"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

def escaneo_servicios_C(target):
    comando = [
        "nmap", "-sV", "-C", "-Pn", "-n", "-vvv", target, "-oN", "nmap_svC.txt"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

def escaneo_agresivo(target):
    comando = [
        "nmap", "-A", "-Pn", "-n", "-vvv", target, "-oN", "nmap_agresivo.txt"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

def escaneo_syn(target):
    comando = [
        "nmap", "-sS", "-Pn", "-n", "-vvv", target, "-oN", "nmap_syn.txt"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

def escaneo_sigiloso(target, nivel):
    comando = [
        "nmap", "-sS", "-T" + str(nivel), "-Pn", "-n", "-vvv", target, "-oN", f"nmap_sigiloso_T{nivel}.txt"
    ]
    print(f"Ejecutando: {' '.join(comando)}")
    subprocess.run(comando)

if __name__ == "__main__":
    objetivo = input("Introduce la IP o dominio objetivo: ")
    print("\nOpciones de escaneo:")
    print("1. Escaneo básico (puertos, --open, --min-rate)")
    print("2. Escaneo de servicios y versiones (-sV)")
    print("3. Detección de sistema operativo (-O)")
    print("4. Guardar resultado en XML")
    print("5. Escaneo de servicios con -sV -C")
    print("6. Escaneo agresivo (-A)")
    print("7. Escaneo SYN sigiloso (-sS)")
    print("8. Escaneos sigilosos con T1, T2, T3, T4")
    opcion = input("Elige una opción (1-8): ")

    if opcion == "1":
        while True:
            min_rate = input("Introduce el valor de --min-rate (ejemplo: 200 o 5000): ")
            if min_rate.isdigit() and int(min_rate) > 0:
                min_rate = int(min_rate)
                break
            else:
                print("Por favor, introduce un número entero positivo.")
        escaneo_basico(objetivo, min_rate)
        print("Escaneo completado. Resultado guardado en nmap_result.txt")
    elif opcion == "2":
        escaneo_servicios(objetivo)
        print("Escaneo completado. Resultado guardado en nmap_servicios.txt")
    elif opcion == "3":
        escaneo_os(objetivo)
        print("Escaneo completado. Resultado guardado en nmap_os.txt")
    elif opcion == "4":
        escaneo_xml(objetivo)
        print("Escaneo completado. Resultado guardado en nmap_result.xml")
    elif opcion == "5":
        escaneo_servicios_C(objetivo)
        print("Escaneo completado. Resultado guardado en nmap_svC.txt")
    elif opcion == "6":
        escaneo_agresivo(objetivo)
        print("Escaneo completado. Resultado guardado en nmap_agresivo.txt")
    elif opcion == "7":
        escaneo_syn(objetivo)
        print("Escaneo completado. Resultado guardado en nmap_syn.txt")
    elif opcion == "8":
        for nivel in range(1, 5):
            escaneo_sigiloso(objetivo, nivel)
        print("Escaneos sigilosos completados. Resultados guardados en nmap_sigiloso_T1.txt, T2.txt, T3.txt, T4.txt")
    else:
        print("Opción no válida.")