# TPE-Redes
Este repositorio contiene la configuración y los archivos necesarios para implementar un Web Application Firewall (WAF) utilizando ModSecurity, en conjunto con un servidor proxy reverso. El objetivo de este proyecto es proporcionar una capa de seguridad adicional para aplicaciones web, protegiéndolas contra diversos tipos de ataques.

Los pasos que seguiremos para implementar el sistema son los siguientes:

1. Configurar un servidor Proxy que funcione como proxy reverso para recibir las peticiones para al menos 2 servidores con web server
2. Configurar un servidor con ModSecurity que reciba las redirecciones del Proxy y chequee la seguridad de las mismas
3. Configurar al menos 3 reglas de solo detección para realizar análisis
4. Configurar al menos 3 reglas de bloqueo
5. Probar al menos 3 ataques para mostrar la respuesta del waf, configurar un página default de respuesta ante detección de anomalía.

## Requerimientos

Para poder levantar el proyecto es necesario contar con lo siguiente
- `docker`
-  `docker compose`

## Herramientas

### ModSecurity
Es el motor del WAF que analiza el tráfico HTTP que pasa a través del proxy reverso. nos permite configurar reglas específicas para detectar y bloquear patrones de ataque, asegurando que solo el tráfico seguro llegue a los servidores web. Tambien se pueden configurar reglas de solo deteccion para poder monitorear ciertas requests.

### Nginx
En este proyecto esta configurado como proxy reverso, el servidor nginx recibe todas las requests entrantes y las redirige a los servidores web. ModSecurity se configura como un modulo del proxy asi puede acceder al trafico HTTP. 

### Docker y Docker compose
Los utilizamos para definir y ejecutar el entorno completo del WAF, incluyendo Nginx con ModSecurity y una webapp local, dentro de contenedores. Estas herramientas permiten poder levantar el sistema de forma consistente sin preocuparnos por el entorno.

## Arquitectura

Este es un diagrama de la arquitectura de la solución del proyecto, donde el servidor proxy reverso funciona como un WAF para proteger dos aplicaciones web: una dentro de la misma red que el WAF y otra alojada en Internet. Si se configura correctamente, un usuario malicioso no podrá atacar las aplicaciones web, mientras que un usuario normal debería poder utilizar las aplicaciones sin problemas.

![arquitectura](./docs/architecture.png)

La aplicación web que se ejecuta dentro de la red del WAF es un contenedor que utiliza la imagen de la aplicación [Juice Shop de OWASP](https://github.com/juice-shop/juice-shop). Esta es una aplicación web de prueba que contiene múltiples vulnerabilidades para propósitos educativos y de entrenamiento en seguridad. La otra aplicación que se ejecuta en Internet es [XSS Game](https://xss-game.appspot.com/), una página web creada por Google para probar y aprender sobre ataques de Cross-Site Scripting.

---

# Instrucciones

## Configurar el servidor proxy
A continuación se detallan los pasos para configurar el servidor proxy para que funcione como un proxy reverso para recibir las peticiones para al menos 2 servidores con web server.
### Construccion

Como mencionamos anteriormente, el servidor proxy se ejecuta en un contenedor de Docker. Para crear este contenedor, utilizamos el Dockerfile ubicado en `./proxy/Dockerfile`. La construcción de un contenedor con Nginx se realiza de la siguiente manera:

```Dockerfile
# A partir de un linux
FROM ubuntu:latest

# Instalamos nginx
RUN apt-get update &&           \
    apt-get install -y nginx=1.24.0-2ubuntu7

#.....otras directivas

# Escuchamos en el puerto 80
EXPOSE 80

# Corremos nginx en primer plano
CMD ["nginx", "-g", "daemon off;"]
```

### Configuracion

Dentro de la carpeta `./proxy/sites/`, tenemos dos archivos de configuración para los sitios web Juiceshop y XSS-Game en Nginx.

Para la aplicación Juiceshop, el archivo de configuración `juiceshop.conf` se configura de la siguiente manera:

```Nginx
server {
    # Puerto y nombre de host
    listen       80;
    server_name juiceshop.local;
    
    #.....otras directivas
    
    location / {
        # Aquí especificamos a dónde se enviarán las solicitudes entrantes.
        proxy_pass http://webapp:3000;
        
        # Configuramos algunos encabezados para enviar al servidor web.
        proxy_set_header Host webapp;
        
        # Indicamos al servidor backend que la URL de referencia es 'http://webapp:3000'.
        proxy_set_header Referer http://webapp:3000;

        # Configuración de encabezados HTTP con informacion util para el servidor web.
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Accept-Encoding "";
        proxy_set_header Accept-Language $http_accept_language;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    #.....otras directivas
}
```

Notar que la URL especificada en proxy_pass es `http://webapp:3000`. Como mencionamos anteriormente, el servidor Juiceshop se ejecuta en un contenedor dentro de la misma red de Docker Compose que el proxy. Por lo tanto, Docker Compose nos permite resolver el nombre webapp a la dirección IP del contenedor correspondiente.

Para la aplicación XSS-Game, el archivo de configuración `xss-game.conf` tiene una configuración similar pero apunta a otro sitio:

```Nginx
server {
    listen 80;
    server_name xss-game.local;

    #.....otras directivas

    location / {
        proxy_pass https://xss-game.appspot.com;

        proxy_set_header Host xss-game.appspot.com;
        proxy_set_header Referer https://xss-game.appspot.com;

        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Accept-Encoding "";
        proxy_set_header Accept-Language $http_accept_language;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    #.....otras directivas
}
```

Estos archivos de configuración determinan cómo Nginx manejará las solicitudes entrantes para cada sitio web, redirigiéndolas al servidor correspondiente y configurando los encabezados necesarios para la comunicación con el servidor web.

## Agregar ModSecurity
A continuación se detallan los pasos para agregar ModSecurity al servidor proxy para que este pueda cumplir la funcion de un WAF.

### Construccion
ModSecurity funciona como un modulo para nginx por lo tanto se debe agregar al Dockerfile del proxy directivas que instalaran ModSecurity y lo configuraran como modulo de nginx. El Dockerfile en `./proxy/Dockerfile` quedara asi:

```Dockerfile
#.....otras directivas

# Instalamos las dependencias necesarias para el módulo de modsecurity
RUN apt-get install -y gcc make build-essential autoconf automake libtool libcurl4-openssl-dev \
    liblua5.3-dev libfuzzy-dev ssdeep gettext pkg-config libgeoip-dev libyajl-dev doxygen \
    libpcre3-dev libpcre2-16-0 libpcre2-dev libpcre2-posix3 zlib1g zlib1g-dev git

# Descargamos modsecurity del repositorio oficial en /opt
WORKDIR /opt
RUN git clone https://github.com/owasp-modsecurity/ModSecurity.git

# Instalamos modsecurity, aqui se compilara desde 0 modsecurity
WORKDIR /opt/ModSecurity
RUN git submodule init
RUN git submodule update
RUN ./build.sh
RUN ./configure
RUN make
RUN make install

# Descargamos el conector que conecta nginx con ModSecurity
WORKDIR /opt
RUN git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git

# Compilamos el modulo utilizando el conector
WORKDIR /opt
RUN wget https://nginx.org/download/nginx-1.24.0.tar.gz
RUN tar -xvzf nginx-1.24.0.tar.gz
WORKDIR /opt/nginx-1.24.0
RUN ./configure --with-compat --add-dynamic-module=/opt/ModSecurity-nginx
RUN make modules

# Copiamos el módulo a la carpeta de módulos de nginx para que este pueda accederlo
RUN cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules-enabled/

# Copiamos la configuracion default
RUN cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf
RUN cp /opt/ModSecurity/unicode.mapping /etc/nginx/unicode.mapping

# Configuramos nginx para que cargue el módulo de modsecurity
# Esto lo hacemos con un prepend
RUN printf '%s\n%s\n' "load_module /etc/nginx/modules-enabled/ngx_http_modsecurity_module.so;" "$(cat /etc/nginx/nginx.conf)" > /etc/nginx/nginx.conf

#.....otras directivas

```

Una vez instalado ModSecurity, lo que queda es activarlo para cada uno de los sitios en la configuracion de nginx. Por lo que debemos agregar las siguientes directivas:

`juiceshop.conf`
```Nginx
    #.....otras directivas
    
    # Activo ModSecurity
    modsecurity on;
    
    # Especifico el archivo de configuracion
    modsecurity_rules_file /etc/nginx/modsecurity.conf;
    
    #.....otras directivas
```

`xss-game.conf`
```Nginx
    #.....otras directivas
    
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity.conf;
    
    #.....otras directivas
```
### Configuracion

Dentro del directorio `./proxy/modsecurity`, se encuentra el archivo de configuración predeterminado de ModSecurity en `modsecurity.conf`. Este archivo contiene la configuración principal de ModSecurity, que incluye reglas de seguridad, configuraciones de auditoría y otras directivas importantes para proteger las aplicaciones web contra ataques comunes.

De forma predeterminada Modsecurity no bloquea el trafico malicioso, solamente lo detecta y lo loguea. Para que modsecurity bloquee el trafico cambiamos la directiva `SecRuleEngine`. El archivo donde se mandan los logs se especifica con la directiva `SecAuditLog`.

```
#.....otras directivas

# La directiva predeterminada era: SecRuleEngine DetectionOnly
SecRuleEngine On 

# Con esta directiva especificamos donde se guardan los logs
SecAuditLog /var/log/modsec_audit.log

#.....otras directivas
```

Listo! Ya tenemos lo necesario para levantar el WAF, ahora podemos configurar algunas reglas

## Definición de Reglas
En esta sección se detallan algunas reglas configuradas en ModSecurity para proteger las aplicaciones web. Incluye tanto reglas de detección como de bloqueo. Estas reglas se encuentran en el archivo `./proxy/modsecurity/custom-rules.conf`. Para obtener más información sobre el lenguaje de reglas de ModSecurity, recomendamos la [documentación oficial de ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/wiki/).

### Reglas de bloqueo
Estas reglas bloquean el trafico si existe un match, esto se hace usando la directiva de acción `deny`.

#### Bloqueo por IP
Estas reglas bloquean el acceso desde direcciones IP específicas o rangos de IP.

```
# Bloqueo la red 192.168.0.0/16
SecRule REMOTE_ADDR "@ipMatch 192.168.0.0/16" "id:10,phase:1,deny"

# Bloqueo la ip 10.0.0.1
SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:10,phase:1,deny"
```

#### Bloqueo fuerza bruta en el login

Estas reglas están diseñadas para detectar y bloquear intentos de fuerza bruta en el path de inicio de sesión.
```
# Inicializa una colección de IP para almacenar el número de intentos de inicio de sesión
SecAction "initcol:ip=%{REMOTE_ADDR},pass,phase:1, id:1"

# Incrementa el contador de intentos de inicio de sesión fallidos cada vez que se accede a /rest/user/login
SecRule REQUEST_URI "^/rest/user/login" "pass,phase:1,setvar:ip.attempts=+1,id:2"

# Reinicia el contador de intentos de inicio de sesión si el estado de la respuesta es exitoso (2xx)
SecRule REQUEST_URI "^/rest/user/login" "chain,pass,phase:3,id:3"
    SecRule RESPONSE_STATUS "^2..$" "setvar:ip.attempts=0,id:4"

# Bloquea el acceso si hay más de 5 intentos de inicio de sesión fallidos
SecRule IP:ATTEMPTS "@gt 5" "phase:1,deny,status:403,id:5"
```

#### Bloqueo de SQL Injection

Esta regla está diseñada para bloquear intentos de SQL injection al buscar patrones en los argumentos de las solicitudes (ARGS). En la expresión regular `(@rx)` incluimos varias keywords de sql y ataques como `' or 1=1 --`.
```
# Bloquea intentos de SQL injection detectando patrones comunes en los argumentos de las solicitudes
SecRule ARGS "@rx (?i:(union select|select.*from|insert into|delete from|drop table|information_schema|or 1=1|benchmark|sleep|load_file|into outfile))" \
    "id:6,\
    phase:2,\
    deny,\
    status:403"
```

#### Bloqueo de XSS
Esta regla está diseñada para bloquear intentos de Cross-Site Scripting (XSS) al buscar patrones de scripts en varias partes de la solicitud. La expresión regular `(@rx)` detecta etiquetas `<script>` y su contenido.
```
# Bloquea intentos de Cross-Site Scripting (XSS) detectando scripts maliciosos en varias partes de la solicitud
SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|REQUEST_COOKIES|REQUEST_BODY "@rx <script[\s\S]*?>.*<\/script>" \
    "id:'7',phase:2,t:none,t:htmlEntityDecode,t:lowercase,deny,status:403"
```

### Reglas de solo detección
En esta sección, definimos reglas que están configuradas únicamente para la detección de ciertos patrones. Estas reglas no bloquearán el tráfico, sino que registrarán los eventos relevantes para su análisis y monitoreo. Estos mensajes se encuentran en el archivo `/var/log/modsec_audit.log` del container del proxy.
#### Detección de user agent
Esta regla detecta solicitudes que utilizan el User-Agent [HTTPie](https://httpie.io/) y registra un mensaje en el log.
```
# Detecto el user agent httpie
SecRule REQUEST_HEADERS:User-Agent "HTTPie" "id:8,log,msg:'Request from HTTPie user agent'"
```

#### Detección de login del administrador
Esta regla detecta intentos de inicio de sesión con credenciales de administrador en la URI `/rest/user/login`.
```
SecRule REQUEST_URI "@contains /rest/user/login" "id:9,phase:2,chain,log,msg:'Attempted login to admin'"
    SecRule REQUEST_BODY "@contains admin@admin.com" "chain,phase:2"
    SecRule REQUEST_BODY "@contains adminpassword" "phase:2"
```

La regla verifica el URI y el cuerpo de la solicitud para detectar las credenciales `admin@admin.com` y `adminpassword` (supongamos que son las credenciales reales del admin). Si se cumplen todas estas condiciones, se registra un mensaje indicando un intento de inicio de sesión con credenciales de administrador.
#### Detección de un error de SQL en la respuesta
Esta regla detecta mensajes de error específicos de SQL en el cuerpo de la respuesta.

```
SecRule RESPONSE_BODY "@contains SQLITE_ERROR: unrecognized token" "id:10,phase:4,log,msg:'SQL error message detected in response'"
```

Esto es útil para identificar posibles vulnerabilidades en la aplicación relacionadas con inyecciones SQL que podrían causar errores en la base de datos.

## Configurar un página default de respuesta ante detección de anomalía

Para configurar una página de respuesta predeterminada que se muestre cuando se detecten ataques, debemos agregar las siguientes directivas a los archivos de configuración de Nginx correspondientes a cada aplicación.

`juiceshop.conf`
```Nginx
    #.....otras directivas

    # Define la página de error para el código de estado 403
    error_page 403 /403.html;
    
    # Configura la ubicación para la página de error 403
    location = /403.html {
        # Si el cliente acepta respuestas en formato JSON, devuelve un mensaje personalizado
        if ($http_accept ~ json) {
            return 403 "You shall not pass";
        }
        
        # De lo contrario, sirve la página de error desde el directorio especificado
        root /usr/share/nginx/html;
    }
    
    #.....otras directivas
```

`xss-game.conf`
```Nginx
    error_page 403 /403.html;

    location = /403.html {
        # Como esta aplicacion no usa json, simplemente sirvo la pagina de error
        root /usr/share/nginx/html;
    }
```

El archivo que contiene el código HTML de la página de respuesta se encuentra en `./proxy/error_pages/403.html`. Este código no es de nuestra autoría y fue obtenido de [CodePen](https://codepen.io/anjanas_dh/pen/ZMqKwb).

## Agregar el CRS de OWASP

Configurar reglas puede ser difícil, y aún más difícil es determinar qué reglas son necesarias para proteger las aplicaciones contra una variedad de ataques. Para ayudar con esto, OWASP proporciona un conjunto de reglas conocido como [CRS (Core Rule Set)](https://owasp.org/www-project-modsecurity-core-rule-set/).

### Construcción

Para instalar el CRS, primero agregamos las siguientes directivas al Dockerfile en `./proxy/Dockerfile`.

```Dockerfile
#.....otras directivas

# Descargamos OWASP-crs para modsecurity
WORKDIR /opt
RUN apt-get install -y wget
RUN wget https://github.com/coreruleset/coreruleset/archive/v3.3.5.tar.gz
RUN tar -xvzf v3.3.5.tar.gz

#.....otras directivas
```

Luego, simplemente indicamos a ModSecurity que incluya las reglas del CRS. Por lo tanto agregamos las siguientes directivas al archivo de configuracion de Modsecurity (`./proxy/modsecurity/modsecurity.conf`)

```
#.....otras directivas

# Incluimos configuracion del OWASP CRS 
Include ./crs-setup.conf

# Incluimos todas las reglas
Include /opt/coreruleset-3.3.5/rules/*.conf

#.....otras directivas
```

Con esto, todas las reglas del CRS están instaladas, proporcionando un nivel adicional de seguridad a nuestras aplicaciones.

### Configuración

Dentro del directorio `./proxy/modsecurity`, se encuentra el archivo de configuración predeterminado del CRS en `crs-setup.conf`. En este archivo, se puede configurar el CRS con diversas opciones, una de las configuraciones posibles es el `paranoia level`. 

Este controla el grado de sensibilidad de las reglas de detección del CRS. Cuanto mayor sea el nivel de paranoia, más estrictas serán las reglas y más probable será que se detecten ataques. Sin embargo, un nivel de paranoia más alto también aumentará la posibilidad de falsos positivos, es decir, la detección incorrecta de actividades legítimas como ataques. Para mayor información consultar [aqui](https://coreruleset.org/docs/concepts/paranoia_levels/). Nosotros utilizamos el nivel de paranoia 1 y lo especificamos con la siguiente directiva

```
SecAction \
 "id:900000,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:tx.paranoia_level=1"
```

De todas formas, incluso con el nivel 1, hemos encontrado algunos falsos positivos con algunas reglas en la aplicación `juiceshop`. Para abordar este problema, podemos excluir reglas conflictivas mediante la adición de las siguientes directivas al archivo `./proxy/modsecurity/modsecurity.conf`.

```
#.....otras directivas

# Especificamos por ID las reglas a excluir
SecRuleRemoveById 920170 920420
```

Esto nos permite excluir reglas específicas del CRS identificadas por su ID, lo que ayuda a reducir los falsos positivos sin comprometer significativamente la seguridad de la aplicación.



---
para armar los contenedores se debe ejecutar el siguiente comando
```sh
docker compose build
```

una vez armadas las imagenes podemos ejecutarlas utilizando
```sh
docker compose up -d
```

para poder ver las paginas a las que le hacemos reverse proxy, primero necesitamos agregar las siguientes lineas a /etc/hosts
```sh
echo -e "127.0.0.1 juiceshop.local\n127.0.0.1 xss-game.local" | sudo tee -a /etc/hosts > /dev/null
```

luego podremos utilizar curl o acceder desde el browser a los urls `juiceshop.local` y `xss-game.local`
