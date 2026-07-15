## CASOS DE USO - SPLUNK

Aqui agregaremos las Consultas SPL para las Detecciones ante posible Ataques.

### Caso de Uso de Fuerza Bruta index = H70 Windows EventCode = 4625

| rename "Dirección de Red de Origen" as IP

| rename "Nombre de estación de trabajo" as MachineNameAtacante

| rename "Nombre de cuenta" as Usuario

| eval tiempo = strftime(_time, "%B %d, %Y - %I:%M:%S %p")

| eval Mensaje = "Login RDP Fallido"

| table Mensaje, IP, Usuario, tiempo

| eval Usuario = mvindex(Usuario, 1)

| sort + tiempo (de menor a mayor organiza los eventos)

| stats count by Mensaje

| save as Alerta → Run on Cron Schedule

(Para establecer un cron son 5 *)

Priority: High Msg: "SE HA DETECTADO UNA ALERTA DE FUERZA BRUTA EN EL [VARIABLE]"

"Los logs van directo al Backend de Splunk"

### Local File Inclusion (LFI) Local File Inclusion (LFI): 

Es una vulnerabilidad que ocurre cuando una aplicación permite que el usuario incluya (cargue o lea) archivos locales del servidor a través de una URL.

Un ataque de tipo LFI puede permitir:

Ver archivos sensibles. Escalar a Remote Code Execution (RCE). Robar credenciales o información interna. Consulta para averiguar si están haciendo LFI (Caso de uso LFI)

index=vps_azure dest_port=80 (ip) "http_status"=404

| stats count by http.url _time src_ip

| rename http.url as url

| eval decoderUrl=urldecode(url)

| eval chequeo=if(match(decoderUrl,".."),"Puntos","Sin Puntos")

| where chequeo="Puntos"

| table decoderUrl count src_ip

Explicación

Todo el código devuelve los siguientes campos:

Decodificación de la URL. Tiempo. Cantidad de intentos (count). Dirección IP. Caso de uso: Fail2Ban index=vps_azure source="/var/log/fail2ban.log"

| rex field=_raw "Ban (?[^\ ]+)"

| stats count by IP

| iplocation IP

| table IP Country count

Explicación

La línea iplocation agrega el país correspondiente a la IP para mostrarlo en la tabla.

Es cuando guardamos la alerta utilizando la opción del SOAR para automatizarla.

### Caso de uso: Exceso de registros de Ping sourcetype=firewall OR sourcetype=network_traffic icmp

| stats count by src_ip dest_ip

| where count > 50

| sort -count

Adicional:

| timechart span=1m count by src_ip

Explicación

Filtra eventos relacionados con el protocolo ICMP. Cuenta cuántos paquetes ICMP hay por IP origen y destino. where count > 50: muestra solo los casos con más de 50 paquetes. sort -count: ordena de mayor a menor cantidad de paquetes. Esto genera una gráfica temporal del tráfico ICMP por IP, ideal para identificar picos.

#### ICMP (Internet Control Message Protocol)

Es un protocolo que se utiliza para enviar mensajes de control y diagnóstico entre dispositivos.

### Caso de uso para ver los comandos que utilizó el atacante (RCE) index=vps_azure source="/home/admin(run)" (IP)

| stats count by _time http.url http.hostname dest_ip

| rename http.url as url

| where url != ""

| eval rce=if(match(url,"cmd|reverse|shell"),"si","no")

| where rce="si"

| rex field=url "cmd=(?<cmd_command>[^&]+)"

| where cmd_command != ""

| eval cmd_command=urldecode(cmd_command)

| table _time cmd_command

Explicación

Busca todos los eventos del servidor que contengan esa IP.

Permite ver qué URLs fueron accedidas, cuántas veces y agrupa los resultados por tiempo, URL, hostname y dirección IP de destino.

Renombra http.url como url.

Filtra los eventos y descarta las URLs vacías.

Es la línea clave: busca si la URL contiene patrones sospechosos que suelen utilizarse en ataques RCE.

Ejemplos:

cmd → ejecución de comandos. reverse → intento de Reverse Shell. shell → comandos relacionados con shells remotas. Si encuentra alguno de esos términos: rce = "si" Caso contrario: rce = "no"

Se queda únicamente con los eventos sospechosos (rce="si").

Utiliza expresiones regulares (Regex) para extraer el valor del parámetro cmd.

Ejemplo: /index.php?cmd=whoami

Extrae: whoami

y lo guarda en el campo cmd_command.

Descarta los resultados vacíos (sin comando detectado).

Decodifica el comando si estaba codificado en la URL.

Ejemplo: cmd=cat%20/etc/passwd ↓ cat /etc/passwd

Muestra una tabla final con: Hora. Comando que el atacante intentó ejecutar. Caso de uso del Evento 5145 Index index = H7O_Windows EventCode = 5145

#### Renombrar los campos:

| rename "Dirección de origen" AS IP

| rename "Nombre del recurso compartido" AS Recurso

| rename "Nombre de cuenta" AS Usuario

| rename "Ruta de acceso de recurso compartido" AS Ruta

| rename "Nombre de destino relativo" AS Archivo

Agregar un mensaje: eval mensaje="Detección de acceso a recurso compartido"

Convertir el tiempo: eval tiempo=strftime(_time,"%d/%m/%Y - %H:%M:%S")

Mostrar: table mensaje, IP, Ruta, Archivo, Recurso, Usuario, tiempo sort + tiempo

Nota:

sort + tiempo ordena los eventos desde el más antiguo al más reciente. ⸻

Explicación

#### Event ID 5145 (Windows Security)

Corresponde a:

“A network share object was checked to determine whether the client can be granted the desired access.”

Cuando un usuario intenta acceder a un archivo o recurso compartido mediante SMB, Windows verifica si tiene permisos para hacerlo.

Qué detecta?

Acceso a un archivo compartido. Intento de acceder a un recurso en un Share de red. Comprobación de permisos antes del acceso. ⸻

¿Qué hace la búsqueda?

Detecta el acceso. Elimina eventos duplicados (si corresponde). Ordena cronológicamente. ⸻

Eventos ID de Windows esperados

Eventos SMB (Compartición de archivos) SMB (Server Message Block) es el protocolo utilizado para compartir:

Archivos Carpetas Impresoras Recursos de red ⸻

#### Event ID 5140

Acceso a un recurso compartido.

Puede indicar:

Acceso a carpetas compartidas. Movimiento lateral (MITRE ATT&CK). Robo de archivos mediante SMB. ⸻

#### Event ID 5145

Comprobación de permisos sobre un recurso compartido.

Windows registra este evento cuando verifica si un cliente posee permisos suficientes para acceder al archivo solicitado.

⸻

Usuarios Event ID 4720

Se creó una cuenta de usuario.

⸻

#### Event ID 4732

Un usuario fue agregado a un grupo local de seguridad (por ejemplo, Administrators).

Puede indicar que un atacante elevó privilegios agregando su usuario al grupo Administradores.

⸻

#### Eventos RDP Event ID 4624

Inicio de sesión exitoso.

Si el Logon Type = 10, corresponde a un inicio mediante RDP.

⸻

#### Event ID 4625

Intento fallido de inicio de sesión.

⸻

#### Event ID 4672

Privilegios especiales asignados al nuevo inicio de sesión.

Suele aparecer cuando inicia sesión un administrador o una cuenta con privilegios elevados.

⸻

#### Puertos importantes

NetBIOS → 139

SMB → 445

RDP → 3389

⸻

#### Event ID 4688

Creación de un nuevo proceso después del login.

Permite identificar qué proceso ejecutó un usuario.

⸻

Caso: Detección de borrado de logs de seguridad

#### Event ID 1102

Corresponde al borrado del registro de auditoría de Windows.

| index=wineventlog

| source="WinEventLog:Security"

| EventCode=1102

Renombrar: Nombre de cuenta

Mostrar: table _time, host, Signature, user

Programar:

Tiempo real (Real-Time) Resultado por evento Severidad: Critical El Event ID 1102 es muy importante porque los atacantes suelen borrar los logs para ocultar sus acciones después de comprometer un equipo.

Programar:

Tiempo real (Real-Time) Resultado por evento Severidad: Critical El Event ID 1102 es muy importante porque los atacantes suelen borrar los logs para ocultar sus acciones después de comprometer un equipo.

Ejemplos:

../../

../../../

../../../etc/passwd

Objetivo:

Acceder a archivos restringidos del servidor.

Riesgo:

Medio/Alto

⸻

### Absolute Path Traversal

Utiliza rutas absolutas del sistema operativo.

Ejemplo Linux: /etc/passwd

Diferencia entre ruta absoluta y relativa

### Ruta absoluta

Comienza desde la raíz del sistema.

Ejemplo: /etc/passwd

Ruta relativa

Depende de la ubicación actual.

Ejemplo: ../../etc/passwd

Path Traversal

Normalmente utiliza rutas relativas (../), aunque algunos ataques también emplean rutas absolutas dependiendo de la vulnerabilidad.

⸻

Comandos / Casos de uso (Splunk)

Un atacante sólo puede ver tu IP privada si

Está dentro de tu red. Comprometió tu equipo. Tiene acceso interno. ⸻

Caso 1

Login exitoso luego de múltiples fallos

index=security EventCode IN (4624,4625)

| stats count(eval(EventCode=4625)) AS Failures

count(eval(EventCode=4624)) AS Success

BY Account_Name, Source_Network_Address
| where Failures > 5 AND Success > 0

Detecta:

Ataques exitosos luego de múltiples intentos. Credential Stuffing. Fuerza bruta exitosa. ⸻

Caso 2

Actividad DNS sospechosa

index=dns

| stats count BY src_ip, query

| where count > 10

Detecta:

Dominios consultados repetidamente. Posible comportamiento de malware. ⸻

Caso 3

DNS Tunneling

index=dns

| eval qlen=len(query)

| where qlen > 50

| stats count BY src_ip, query

Detecta:

Dominios excesivamente largos. Posible exfiltración de datos mediante DNS. ⸻

Caso 4

Escaneo de puertos

index=network

| stats dc(dest_port) AS Ports BY src_ip

| where Ports > 20

Detecta:

Una IP intentando conectarse a muchos puertos distintos. Reconocimiento previo a un ataque (Port Scanning).
