# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors    #https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os            # Obtener ruta y extension
from datetime import datetime, timedelta # Fechas de los mensajes HTTP
import calendar
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging      # Para imprimir logs


REQUEST_RE = re.compile(
    r'(?P<Peticion>[A-Z]+)\s+'
    r'(?P<Objeto>/[^ \r\n]*)\s*'
    r'(?P<Version>HTTP/(?:1\.0|1\.1|2\.0))?\r\n'
    r'(?P<Headers>(?:(?:[A-Za-z-]+):[^\r\n]*\r\n)*)'
    r'\r\n',
    re.MULTILINE
)

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+%40[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def parse_request(text):
    m = REQUEST_RE.search(text)
    if not m:
        return None

    headers_block = m.group("Headers")
    headers = {}
    for line in headers_block.splitlines():
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    
    version = m.group("Version")
    if version == None:
        version = "HTTP/1.1"
    
    return {
        "peticion": m.group("Peticion"),
        "objeto": m.group("Objeto"),
        "version": version,
        "headers": headers,
    }

# uso:
# result = parse_request(raw_http_text)
# print(result["headers"].get("cookie"))

def parse_email(text):
    m = EMAIL_RE.search(text)
    if not m:
        return None
    return m


BUFSIZE = 8192 # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 33.0 # Timout para la conexión persistente
MAX_ACCESOS = 10


# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js","ico":"image/icon"}


# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


# Esta función envía datos (data) a través del socket cs. Devuelve el número de bytes enviados.
def enviar_mensaje(cs, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    cs.sendall(data)
    return len(data)
    

def comprobarRequest(datos):
    # expresion regular
    pass


# Esta función recibe datos a través del socket cs. Leemos la información que nos llega. recv() devuelve un string con los datos.
def recibir_mensaje(cs):
    peticion=""
    while True:
        rsublist, wsublist, xsublist = select.select([cs],[],[],TIMEOUT_CONNECTION) # Se bloquea hasta que llega un socket o hasta que salta el timeout
        if not rsublist:
            logger.info("Tiempo de espera ({0}s) excedido. Cerrando conexión.".format(TIMEOUT_CONNECTION))
            break
       
        datos=cs.recv(BUFSIZE)
    
        if not datos: # LLegan datos vacíos si el cliente cerró la conexión
            logger.info("El cliente cerró la conexión.")
            break
        peticion += datos.decode('utf-8')
        if "\r\n\r\n" in peticion or "\n\n" in peticion:
            break
    return peticion


def createResponse(contentLength, contentType, cookieCounter):
    
    response=("HTTP/1.1 200 OK\r\n" + 
              "Date: {}\r\n" + 
              "server: ToDo PONERNOMBRESERVIDOR\r\n" + 
              "Connection: Keep-Alive\r\n" + 
              "Keep-Alive: timeout=5, max=33\r\n" +
              "Content-Length: {}\r\n" +
              "Content-Type: {}\r\n" + 
              "Set-Cookie: {}\r\n\r\n" 
              ).format(
                  datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
                  contentLength,
                  contentType,
                  cookieCounter
              )
    return response
    
def createResponseError(code, message, contentLength, contentType):
    cabecera = (
        "HTTP/1.1 {} {}\r\n"
        "Date: {}\r\n"
        "Server: ToDo PonerNombreServidor\r\n"
        "Connection: keepAlive\r\n"
        "Content-Length: {}\r\n"
        "Content-Type: {}\r\n\r\n"
    ).format(
        code,
        message,
        datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        contentLength,
        contentType
    )
    return cabecera

def cerrar_conexion(cs):
    return cs.close()

def process_cookies(headers,  cs,index):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
# Modificar función para que reciba el mensaje entero y que solo sume si es /

    cookie_value = headers.get("cookie")
    if cookie_value == None: 
        return 1
    cookie_value = int(cookie_value)
    if cookie_value == MAX_ACCESOS:
        return MAX_ACCESOS
    elif cookie_value >= 1 or cookie_value < MAX_ACCESOS:
        if index:
            cookie_value = cookie_value + 1
        return cookie_value
    else:
        return 1


def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)

        * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()

            * Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
              sin recibir ningún mensaje o hay datos. Se utiliza select.select

            * Si no es por timeout y hay datos en el socket cs.
                * Leer los datos con recv.
                * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
                    * Devuelve una lista con los atributos de las cabeceras.
                    * Comprobar si la versión de HTTP es 1.1
                    * Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".
                    * Leer URL y eliminar parámetros si los hubiera
                    * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                    * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                    * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
                    * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                      el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                      Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    * Obtener el tamaño del recurso en bytes.
                    * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
                    * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
                      las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                      Content-Length y Content-Type.
                    * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
                    * Se abre el fichero en modo lectura y modo binario
                        * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                        * Cuando ya no hay más información para leer, se corta el bucle

            * Si es por timeout, se cierra el socket tras el período de persistencia.
                * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
    """
    
    # TODO: Hacer una funcion de responseError

    while (True):
        index=False
        datos = recibir_mensaje(cs)
        if not datos:
            break
        lineas = datos.splitlines()
        lineaPeticion = lineas[0]
        partesPeticion = lineaPeticion.split()
        if len(partesPeticion) < 3:
            ruta_error = os.path.join(webroot, "400.html")
            file_size=os.stat(ruta_error).st_size
            _,extension_con_punto=os.path.splitext(ruta_error)
            extension=extension_con_punto[1:]
            content_type=filetypes.get(extension,"application/octet-stream")
            logger.error("Petición incorrecta: %s", lineaPeticion)

            resp = createResponseError(400, "Bad Request", file_size, content_type)
            enviar_mensaje(cs, resp)
            logger.debug(ruta_error)
            with open(ruta_error, "rb") as f:
                while True:
                    error=f.read(BUFSIZE)
                    if not error:
                        break
                    enviar_mensaje(cs, error)
            return        
            

        result = parse_request(datos)
        if result is None:
               break
        
        if result["version"]=="HTTP/1.1":
            
            if result["peticion"]=="GET" or result["peticion"]=="POST":
               
                url=result["objeto"]
                if url == "/":
                    filename = "index.html"
                    index= True
                else:
                     filename = url.lstrip("/") # Quitamos la barra del principio (ej: "/foto.jpg" -> "foto.jpg")
                
                # Tratamiento correo
                if filename[0] == "?":
                    correo = str(filename.replace("?email=", "", 1))
                    correo = parse_email(correo)
                    if correo == None:
                        filename = "406.html"
                    else:
                        filename = "200.html"


                ruta_absoluta=os.path.join(webroot,filename)
                logger.info(ruta_absoluta)
                if os.path.isfile(ruta_absoluta):
                    for name, value in result["headers"].items():
                        print("{}: {}".format(name, value))                    
                    
                    file_size=os.stat(ruta_absoluta).st_size
                    _,extension_con_punto=os.path.splitext(ruta_absoluta)
                    extension=extension_con_punto[1:]
                    content_type=filetypes.get(extension,"application/octet-stream") # Por defecto: datos binarios sin especificar
                    
                    cookie_counter = process_cookies(result["headers"], cs,index)
                    if cookie_counter == MAX_ACCESOS:
                        ruta_error = os.path.join(webroot,"403.html")
                        file_size=os.stat(ruta_error).st_size
                        _,extension_con_punto=os.path.splitext(ruta_error)
                        extension=extension_con_punto[1:]
                        content_type=filetypes.get(extension,"application/octet-stream")
                        logger.error("Archivo no encontrado: %s",ruta_absoluta)
        
        
                        resp = createResponseError(403, "Forbidden",file_size, content_type)
                        enviar_mensaje(cs, resp)
                        logger.debug(ruta_error)
                        with open(ruta_error, "rb") as f:
                            while True:
                                error=f.read(BUFSIZE)
                                if not error:
                                    break
                                enviar_mensaje(cs,error)
                        return
                    response=createResponse(file_size, content_type, cookie_counter)
                    enviar_mensaje(cs,response)
                    logger.debug(ruta_absoluta)
                    with open(ruta_absoluta, "rb") as f:
                        while True:
                            contenido=f.read(BUFSIZE)
                            if not contenido:
                                break
                            enviar_mensaje(cs,contenido)
                            
                else:
                    ruta_error = os.path.join(webroot,"404.html")
                    file_size=os.stat(ruta_error).st_size
                    _,extension_con_punto=os.path.splitext(ruta_error)
                    extension=extension_con_punto[1:]
                    content_type=filetypes.get(extension,"application/octet-stream")
                    logger.error("Archivo no encontrado: %s",ruta_absoluta)
    
    
                    resp = createResponseError(404, "Not Found",file_size, content_type)
                    enviar_mensaje(cs, resp)
                    logger.debug(ruta_error)
                    with open(ruta_error, "rb") as f:
                        while True:
                            error=f.read(BUFSIZE)
                            if not error:
                                break
                            enviar_mensaje(cs,error)
                    return
            else:
                ruta_error = os.path.join(webroot, "405.html")
                file_size=os.stat(ruta_error).st_size
                _,extension_con_punto=os.path.splitext(ruta_error)
                extension=extension_con_punto[1:]
                content_type=filetypes.get(extension,"application/octet-stream")
                logger.error("Método no permitido: %s", result["peticion"])

                resp = createResponseError(405, "Not Allowed", file_size, content_type)
                enviar_mensaje(cs, resp)
                logger.debug(ruta_error)
                with open(ruta_error, "rb") as f:
                    while True:
                        error=f.read(BUFSIZE)
                        if not error:
                            break
                        enviar_mensaje(cs, error)
                return

# Probarlo.
# Crear los html de error
# Crear la funcion error que le pasas code

"""
process web req (cs
    recv(cs)
    parsear y comprobar que existen y estan bien
    construir response
    send (response, cs)
    [cs] = select ([cs],[],[],[,timeout])
    si [cs] esta vacia envio y cierro sino
    recv(cs)
    parsear y comprobar que existen y estan bien
    responde
    send (response, cs)
        [cs] = select ([cs],[],[],[,timeout])
    si [cs] esta vacia envio y cierro sino
    recv(cs)
    parsear y comprobar que existen y estan bien
    responde
    send (response, cs)
"""


""" Función principal del servidor"""
def main():
    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()


        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))
        
        # Crea un socket TCP (SOCK_STREAM)
        mySocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)
        # Permite reusar la misma dirección previamente vinculada a otro proceso
        mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Vinculamos el socket a una IP y puerto elegidos
        mySocket.bind((args.host, args.port))
        # Escucha conexiones entrantes
        mySocket.listen()
        
        # Bucle infinito para mantener el servidor activo indefinidamente
        while (True):
            # Aceptamos la conexión
            client_socket, client_direction = mySocket.accept()
            
            # Creamos un proceso hijo
            pid = os.fork()

            # Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()
            if pid == 0:
                cerrar_conexion(mySocket)
                process_web_request(client_socket, args.webroot)
                cerrar_conexion(client_socket)
                sys.exit(0)
            # Si es el proceso padre cerrar el socket que gestiona el hijo.
            else:
                cerrar_conexion(client_socket)
            
    except KeyboardInterrupt:
        True


if __name__== "__main__":
    main()
