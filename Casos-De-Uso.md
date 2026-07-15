## CASOS DE USO - SPLUNK

Aqui agregaremos las Consultas SPL para las Detecciones ante posible Ataques.

#### Caso de Uso de Fuerza Bruta

index = H70  Windows  EventCode = 4625

| rename "Dirección de Red de Origen" as IP
| rename "Nombre de estación de trabajo" as MachineNameAtacante
| rename "Nombre de cuenta" as Usuario
| eval tiempo = strftime(_time, "%B %d, %Y - %I:%M:%S %p")
| eval Mensaje = "Login RDP Fallido"
| table Mensaje, IP, Usuario, tiempo
| eval Usuario = mvindex(Usuario, 1)
| sort + tiempo   *(de menor a mayor organiza los eventos)*
| stats count by Mensaje
| save as Alerta → Run on Cron Schedule

(Para establecer un cron son 5 *)

Priority: High
Msg: "SE HA DETECTADO UNA ALERTA DE FUERZA BRUTA EN EL [VARIABLE]"

"Los logs van directo al Backend de Splunk"

#### Local File Inclusion (LFI)

Local File Inclusion (LFI): es una vulnerabilidad que ocurre cuando una aplicación permite que el usuario incluya (cargue o lea) archivos locales del servidor a través de una URL.

Un ataque de tipo LFI puede permitir:

* Ver archivos sensibles.
* Escalar a Remote Code Execution (RCE).
* Robar credenciales o información interna.

Consulta para averiguar si están haciendo LFI (Caso de uso LFI)

index=vps_azure dest_port=80 (ip) "http_status"=404

| stats count by http.url _time src_ip
| rename http.url as url
| eval decoderUrl=urldecode(url)
| eval chequeo=if(match(decoderUrl,"\.\."),"Puntos","Sin Puntos")
| where chequeo="Puntos"
| table decoderUrl count src_ip

Explicación

Todo el código devuelve los siguientes campos:

* Decodificación de la URL.
* Tiempo.
* Cantidad de intentos (count).
* Dirección IP.

#### Caso de uso: Fail2Ban

index=vps_azure source="/var/log/fail2ban.log"

| rex field=_raw "Ban (?<IP>[^\ ]+)"
| stats count by IP
| iplocation IP
| table IP Country count

Explicación

La línea iplocation agrega el país correspondiente a la IP para mostrarlo en la tabla.

Es cuando guardamos la alerta utilizando la opción del SOAR para automatizarla.

#### Caso de uso: Exceso de registros de Ping

sourcetype=firewall OR sourcetype=network_traffic icmp

| stats count by src_ip dest_ip
| where count > 50
| sort -count

Adicional:

| timechart span=1m count by src_ip

Explicación

* Filtra eventos relacionados con el protocolo ICMP.
* Cuenta cuántos paquetes ICMP hay por IP origen y destino.
* where count > 50: muestra solo los casos con más de 50 paquetes.
* sort -count: ordena de mayor a menor cantidad de paquetes.

Esto genera una gráfica temporal del tráfico ICMP por IP, ideal para identificar picos.

ICMP (Internet Control Message Protocol)

Es un protocolo que se utiliza para enviar mensajes de control y diagnóstico entre dispositivos.

#### Caso de uso para ver los comandos que utilizó el atacante (RCE)

0. index=vps_azure source="/home/admin(run)" (IP)

1. | stats count by _time http.url http.hostname dest_ip

2. | rename http.url as url

3. | where url != ""

4. | eval rce=if(match(url,"cmd|reverse|shell"),"si","no")

5. | where rce="si"

6. | rex field=url "cmd=(?<cmd_command>[^&]+)"

7. | where cmd_command != ""

8. | eval cmd_command=urldecode(cmd_command)

9. | table _time cmd_command

Explicación

0. Busca todos los eventos del servidor que contengan esa IP.

1. Permite ver qué URLs fueron accedidas, cuántas veces y agrupa los resultados por tiempo, URL, hostname y dirección IP de destino.

2. Renombra http.url como url.

3. Filtra los eventos y descarta las URLs vacías.

4. Es la línea clave: busca si la URL contiene patrones sospechosos que suelen utilizarse en ataques RCE.

Ejemplos:

* cmd → ejecución de comandos.
* reverse → intento de Reverse Shell.
* shell → comandos relacionados con shells remotas.

Si encuentra alguno de esos términos:
rce = "si"
Caso contrario:
rce = "no"

5. Se queda únicamente con los eventos sospechosos (rce="si").

6. Utiliza expresiones regulares (Regex) para extraer el valor del parámetro cmd.

Ejemplo: /index.php?cmd=whoami

Extrae: whoami

y lo guarda en el campo cmd_command.

7. Descarta los resultados vacíos (sin comando detectado).

8. Decodifica el comando si estaba codificado en la URL.

Ejemplo: cmd=cat%20/etc/passwd
↓
cat /etc/passwd

9. Muestra una tabla final con:

* Hora.
* Comando que el atacante intentó ejecutar.
