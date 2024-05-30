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

Este es un diagrama de la arquitectura de la solución del proyecto, donde el servidor proxy reverso funciona como un WAF para proteger dos aplicaciones web: una dentro de la red del WAF y otra alojada en Internet. Si se configura correctamente, un usuario malicioso no podrá atacar las aplicaciones web, mientras que un usuario normal debería poder utilizar las aplicaciones sin problemas.

![arquitectura](./docs/architecture.png)

## Instrucciones

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
