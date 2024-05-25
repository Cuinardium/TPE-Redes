FROM ubuntu:latest

# instalamos nginx
RUN apt-get update &&           \
    apt-get install -y nginx=1.24.0-2ubuntu7

# Dependencias para el módulo de modsecurity
RUN apt-get install -y gcc make build-essential autoconf automake libtool libcurl4-openssl-dev \
    liblua5.3-dev libfuzzy-dev ssdeep gettext pkg-config libgeoip-dev libyajl-dev doxygen \
    libpcre3-dev libpcre2-16-0 libpcre2-dev libpcre2-posix3 zlib1g zlib1g-dev git

# Descargamos modsecurity
WORKDIR /opt
RUN git clone https://github.com/owasp-modsecurity/ModSecurity.git

# Instalamos modsecurity
WORKDIR /opt/ModSecurity

RUN git submodule init
RUN git submodule update

RUN ./build.sh
RUN ./configure

RUN make
RUN make install

# Descargamos el conector de nginx para ModSecurity
WORKDIR /opt
RUN git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git

# Descargamos nginx con soporte para modsecurity
WORKDIR /opt
RUN apt-get install -y wget
RUN wget https://nginx.org/download/nginx-1.24.0.tar.gz
RUN tar -xvzf nginx-1.24.0.tar.gz
WORKDIR /opt/nginx-1.24.0

RUN ./configure --with-compat --add-dynamic-module=/opt/ModSecurity-nginx
RUN make modules

# Copiamos el módulo de modsecurity a la carpeta de módulos de nginx
RUN cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules-enabled/

RUN cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.conf
RUN cp /opt/ModSecurity/unicode.mapping /etc/nginx/unicode.mapping

# Configuramos nginx para que cargue el módulo de modsecurity, prepend
# printf '%s\n%s\n' "to be prepended" "$(cat text.txt)" >text.txt
RUN printf '%s\n%s\n' "load_module /etc/nginx/modules-enabled/ngx_http_modsecurity_module.so;" "$(cat /etc/nginx/nginx.conf)" > /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

