# dhcp_Server
Servidor DHCP escrito en python - DHCP server written in python

Prueba de concepto original no funcional: http://projects2009developer.files.wordpress.com/2009/03/scapy.pdf
Modificado para que funcionara correctamente por: @kr1shn4murt1
Referencias: http://tools.ietf.org/html/rfc2131 , http://tools.ietf.org/html/rfc2132
Fecha: Septiembre 11 - 2013
Dependencias: Ejecutarse con python 2.6.x o 2.7.x , tener scapy instalado en la maquina desde donde se ejecuta
Este script actua como un servidor DHCP escuchando peticiones por la interfaz de red escogida, entrega la informacion relevante de direccionamiento ip a un cliente que la solicite.

# Proposito inicial del script

El script se encontro mientras se buscaba una opcion para no tener que instalar un servidor DHCP completo antes de iniciar un ataque de hombre en el medio con un rogue AP, no hay muchas opciones de scripts portables que funcionen como servidor DHCP y el proceso de instalar y configurar un servidor DHCP en linux es engorroso.

# Intrucciones

* Si se usa el script desde kali linux este ya tiene todo lo necesario para que funcione, si se va a ejecutar desde otra       
  distribucion linux continuar con las siguientes instrucciones:
* Se debe tener python 2.7.x instalado para ejecutar el script
* Se debe tener scapy instalado
* Descargar el script  dhcp_Server_St.py
* Se debe abrir el script con un editor de texto y cambiar el valor de las siguientes variables:

 ip_Servidor="172.16.185.128"        // Esta varible es la ip del servidor que se va a entregar al cliente que solicite DHCP

 ip_cliente="172.16.185.12"          // Esta es la ip que se entregara al cliente que solicite

 mac_Servidor="00:50:56:34:56:ad"    // Aqui se debe poner la mac del servidor donde se ejecuta el script

 mascara_Subred="255.255.255.0"      // Esta es la mascara de subred a entegar

 puerta_Enlace='172.16.185.128'      // Esta es la puerta de enlace que se asignara al cliente que solicita el DHCP

 interfaz_A_Sniffear='eth6'          // Este es el nombre de la interfaz de red del sistema desde donde se ejecuta el script, por alli escuchara las peticiones DHCP para responderlas.
 
* Luego de cambiar el valor de las variables por las deseadas ejecutar el script desde la linea de comandos asi:
  python dhcp_Server_St.py

# NOTAS ADICIONALES

* El poceso de correcion del script original y para poder modificarlo para que funcionara correctamente se observo con wireshark toda la interaccion de paquetes que ocurre al un cliente conectarse a una red y solicitar direccionamiento ip, para hcerlo envia un paquete de broadcast para ver quien es el servidor DHCP, sl servidor DHCP presente en la red responde y ofrece entregarle direccionamiento ip al cliente, el cliente acepta y esta informacion queda matriculada en su tarjeta de red para correcto funcionamiento de su comunicacion en la red
* Se leyo el RFC del protocolo DHCP para entender la interaccion de los paquetes, los nombres de los campos y demas
  http://tools.ietf.org/html/rfc2131 , http://tools.ietf.org/html/rfc2132
* El script no tenia el campo "xid" lo que hacia que solo entregara ip a clientes windows XP que lo solicitaran, no entegaba   
  direccionamiento ip a clientes con sistema operativo linux o Windows 7, al agregar dicho campo "xid" ya funciono sin problema

# TODO: (Listado de cosas a mejorar)

* Designar un rango de ips a entregar por ahora solo entrega 1.
* Agregar multihilo
* Agregar soporte para que funcione en redes inalambricas, por ahora solo funciona en redes ethernet cableadas
* Agregar otras funciones para ejecutar ataque informáticos como dhcp spoofing



