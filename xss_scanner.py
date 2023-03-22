import requests
import threading
import argparse
import queue
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Obtener todos los formularios HTML presentes en la URL recibida como parametro
def get_forms(url, cookie=None):
    # Seteo la variable headers con los headers que se requieren para enviar un http request
    headers = {"Content-Type": "text/html; charset=utf-8"}
    # Se comprueba si se especifico una cookie para agregarsela al header
    if cookie:
        headers["Cookie"] = cookie
    response = requests.get(url, headers=headers)
    # Se verifica si la respuesta es de tipo HTML para pasarselo a beatifulsoup
    if 'text/html' in response.headers.get('content-type'):
        # Se extraen los formularios del sitio
        soup = BeautifulSoup(response.content, "html.parser")
    else:
        print(f"[!] No se pudo analizar el contenido de {url} porque no es HTML.")
        return []
    return soup.find_all("form") # Devuelve una lista con todos los formularios del sitio

# Obtener la info de los forms
def get_form_info(form):
    # Se crea un diccionario con la info del formulario
    info = {}
    info["action"] = form.attrs.get("action", "").lower()
    info["method"] = form.attrs.get("method", "get").lower()
    # Se crea un diccionario de los inputs que se encuentren en el formulario
    info["inputs"] = []
    # Bucle para obtener la info de cada <input>
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        info["inputs"].append({"type": input_type, "name": input_name})
    return info # se devuelve el diccionario con los inputs

# Enviar formulario
def submit_form(form_info, url, value, cookie=None):
    # Se concatena la url con la accion y se guarda en url_dest
    url_dest = urljoin(url, form_info["action"])
    parsed_url = urlparse(url_dest)
    # Se comprueba que la url sea valida
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"[-] URL inválida: {url_dest}")
        return None
    
    inputs = form_info["inputs"]
    data = {}
    # Se crea un diccionario con los headers y si se especifico una cookie se le agrega a este
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    if cookie:
        headers["Cookie"] = cookie
    # Se itera en cada input y se verifica si el tipo de input es "text" o "search"
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value
    # Se envia la solicitud http segun el metodo en form_info
    if form_info["method"] == "post":
        response = requests.post(url_dest, data=data, headers=headers)
    else:
        response = requests.get(url_dest, params=data, headers=headers)
    # Si la respuesta nos devuelve un codigo de estado mayor o igual a 400 se mostrara un mensaje de error
    if response.status_code >= 400:
        print(f"[-] Error al enviar la solicitud a {url_dest}: {response.status_code}")
        return None
    return response # Devuelve la respuesta de solicitud http

# Obtener todos los links dentro del mismo dominio
def get_links(url, cookie=None):
    # Se establece el header y la cookie si es que se especifico
    headers = {"Content-Type": "text/html; charset=utf-8"}
    if cookie:
        headers["Cookie"] = cookie
    # Se realiza la peticion http get
    response = requests.get(url, headers=headers)
    # Se verifica si la respuesta de HTML utilizando beatifulsoup
    if 'text/html' in response.headers.get('content-type'):
        soup = BeautifulSoup(response.content, "html.parser")
    else:
        print(f"[!] No se pudo analizar el contenido de {url} porque no es HTML.")
        return []
    # se crea un arreglo con los links y se utiliza la bs para obtenerlos
    links = []
    for link in soup.find_all("a"):
        href = link.get("href")
        if href:
            link_url = urljoin(url, href)
            # Se comprueba que los links pertenezcan al mismo dominio que la url original para agregarlos
            if link_url.startswith(url):
                links.append(link_url)
    return links # devuelve la lista de los links con el mismo dominio

# Detecta XSS en la url especificada
def scan_xss(url, lock, cookie=None):
    # se llama a get_forms para obtener los formularios del sitio
    forms = get_forms(url, cookie)
    print(f"[+] Se encontraron {len(forms)} formulario(s) en {url}.")
    # se especificca el payload XSS
    payload = "<script>alert('xss')</script>"
    vulnerable = False
    # se itera en todos los forms y se envia el payload
    for form in forms:
        form_info = get_form_info(form)
        response = submit_form(form_info, url, payload)
        # Si ocurre un error en la respuesta se imprimira un mensaje y seguira con el siguiente form
        if response is None:
            print(f"[-] Error al enviar la solicitud a {urljoin(url, form_info['action'])}")
            continue
        content = response.content.decode()
        # Se comprueba si el payload se refleja en el contenido de la pagina para ver si es vulnerable
        if payload in content:
            print(f"[!!!] XSS detectado en {url} [!!!]")
            # Se imprime la info del form
            print("[*] Informacion del formulario:")
            for field in form_info["inputs"]:
                if field['name'] is not None:
                    print(f"\tName:   {field['name']}")
                    print(f"\tType:   {field['type']}")
                else:
                    print(f"\tName:   (sin nombre)")
                    print(f"\tType:   {field['type']}")
                if field['type'] == 'submit':
                    if 'value' in field:
                        print(f"\tValue:  {field['value']}")
                    else:
                        print("\tValue:  (sin valor)")
                print("")
            # Se guarda la info en un archivo de texto detallando la URL afectada y la info del formulario
            with open("resultado_scan.txt", "a") as f:
                f.write(f"[!] URL vulnerable: {url} [!]\n")
                f.write("[*] Informacion del formulario:\n")
                for field in form_info["inputs"]:
                    if field['name'] is not None:
                        f.write(f"\tName:   {field['name']}\n")
                        f.write(f"\tType:   {field['type']}\n")
                    else:
                        f.write(f"\tName:   (sin nombre)\n")
                        f.write(f"\tType:   {field['type']}\n")
                    if field['type'] == 'submit':
                        if 'value' in field:
                            f.write(f"\tValue:  {field['value']}\n")
                        else:
                            f.write("\tValue:  (sin valor)\n")
                    f.write("\n")
            vulnerable = True
        else:
            print(f"[-] No se detectaron vulnerabilidades XSS en: {url}")
        # variable global que reflejara si se detecto o no una vulnerabilidad XSS, se utiliza lock para actualizarla de manera efecta por ser multi-hilo
        if lock.acquire(timeout=1):
            try:
                global vulnerable_global
                if vulnerable:
                    vulnerable_global = True
            finally:
                lock.release()
    if vulnerable:
        return True
    else:
        return False

# Funcion principal, llama a scan_xss para buscar XSS en todos los links del mismo dominio
def scan_xss_recursive(url, cookie=None, threads=1):
    global vulnerable_global
    vulnerable_global = False
    # objeto lock para el multi-hilo
    lock = threading.Lock()
    links_to_scan = queue.Queue()
    links_to_scan.put(url)
    scanned_links = []
    # se iterara cada url hasta que no queden links para escanear 
    while not links_to_scan.empty():
        current_url = links_to_scan.get()
        # Se comprueba si la url ya fue escaneada
        if current_url not in scanned_links:
            scanned_links.append(current_url)
            print(f"[-] Explorando {current_url}")
            # se llama a get_links para obtener todos los links del sitio actual
            links = get_links(current_url, cookie)
            threads_list = []
            # Se escanea cada link utilizando hilos
            for link in links:
                t = threading.Thread(target=scan_xss, args=(link, lock, cookie))
                threads_list.append(t)
            for thread in threads_list:
                thread.start()
            for thread in threads_list:
                thread.join()
            # Se agrega cada link a la cola
            for link in links:
                links_to_scan.put(link)
            # Se actualiza la variable vulnerable_global si se encontro XSS en el sitio actual
            vulnerable_global = vulnerable_global or scan_xss(current_url, lock, cookie)
    return vulnerable_global  # Si se detecto un XSS en cualquier formulario devolvera True, en el caso contrario False

if __name__ == "__main__":
    # Se utiliza argparse obtener los argumentos de la consola
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="URL a escanear")
    parser.add_argument("-t", "--threads", help="numero de threads a usar", type=int, default=1)
    parser.add_argument("-c", "--cookie", help="cookie a usar")
    args = parser.parse_args()
    url = args.url
    cookie = args.cookie
    threads = args.threads
    # Se llama la funcion scan_xss_recursive para escanear la url
    print(scan_xss_recursive(url, cookie))
