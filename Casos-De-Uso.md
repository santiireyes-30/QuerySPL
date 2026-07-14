Casos de uso de Splunk
24 de noviembre de 2021 - Tiempo de lectura: 72 minutos
Etiquetas: Splunk

1- Manipulación del registro de auditoría de Windows
Compruebe si se ha manipulado alguna vez los registros de auditoría de Windows.

index=__your_sysmon_index__ (sourcetype=wineventlog AND (EventCode=1102 OR EventCode=1100)) OR (sourcetype=wineventlog AND EventCode=104)
| stats count by _time EventCode Message sourcetype host
2- Encontrar archivos grandes subidos a la web
Detecta cargas de archivos grandes que podrían indicar una filtración de datos en tu red.

index=__your_sysmon_index__ sourcetype=websense*
| where bytes_out > 35000000
| table _time src_ip bytes* uri
3. Detección de malware recurrente en el host.
Utilizar los registros antivirus para detectar si el malware reaparece en un equipo después de haber sido eliminado.

index=__your_sysmon_index__ sourcetype=symantec:*
| stats count range(_time) as TimeRange by Risk_Name, Computer_Name
| where TimeRange>1800
| eval TimeRange_In_Hours = round(TimeRange/3600,2), TimeRange_In_Days = round(TimeRange/3600/24,2)
4-Detección de ataques de fuerza bruta
Un ataque de fuerza bruta consiste en múltiples intentos de inicio de sesión utilizando muchas contraseñas por parte de un usuario/atacante no autorizado con la esperanza de adivinar finalmente la contraseña correcta.

index=__your_sysmon_index__ sourcetype=winxsecurity user=* user!""
| stats count(eval(action="success")) as successes count(eval(action="failure")) as failures by user, ComputerName
| where successes>0 AND failures>100
Windows

index=windows source="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count by _time,user,host,src,action
| where count >= 5
Linux

index=linux source="/var/log/auth.log" "Failed password"
| bin _time span=5m
| stats count by _time,user,host,src,action
| where count >= 5
5- Detección de comunicaciones web no cifradas
Detecta comunicaciones web no cifradas que podrían provocar una filtración de datos.

index=__your_sysmon_index__ sourcetype=firewall_data dest_port!=443 app=workday*
| table _time user app bytes* src_ip dest_ip dest_port
6- Identificación de usuarios web por país
Utilice las direcciones IP en sus datos para informar y visualizar la ubicación de los usuarios.

index=web sourcetype=access_combined
| iplocation clientip
| geostats dc(clientip) by Country
7- Identificación de contenido web lento
Un sitio web que carga lentamente no solo puede frustrar a los usuarios, sino que también puede perjudicar su posicionamiento en los motores de búsqueda.

index=web sourcetype=ms:iis:auto OR sourcetype=apache: access
| stats avg(response_time) as art by uri_path
| eval "Average Response Time" = round(art,2)
| sort -"Average Response Time"
| table uri_path, "Average Response Time"
8- Búsqueda de nuevas cuentas de administrador local
Con frecuencia, un ataque incluye la creación de un nuevo usuario, seguida de la elevación de sus permisos a nivel de administrador.

index=win_servers sourcetype=windows:security EventCode=4720 OR (EventCode=4732 Administrators)
| transaction Security_ID maxspan=180m
| search EventCode=4720 EventCode=4732
| table _time, EventCode, Recurity_ID, SamAccountName
9- Cómo encontrar inicios de sesión interactivos desde cuentas de servicio
La mayoría de las cuentas de servicio nunca deberían iniciar sesión interactivamente en los servidores.

index=systems sourcetype=audit_logs user=svc_*
| stats earliest(_time) as earliest latest(_time) as latest by user, dest
| eval isOutlier=if(earliest >= relative_time(now(), "-1d@d"), 1, 0)
| convert ctime(earliest) ctime(Latest)
10- Tendencia del volumen de registros
Visualizar el número de eventos registrados por una aplicación puede proporcionar un indicador sencillo pero potente del estado de la aplicación o de los cambios en el comportamiento del código o del entorno.

|tstats prestats=t count WHERE index=apps by host _time span=1m
|timechart partial=f span=1m count by host limit=0
11- Detección básica de tráfico TOR
Utilice los datos del cortafuegos para detectar el tráfico TOR en su red.

index=network sourcetype=firewall_data app=tor src_ip=*
| table _time src_ip src_port dest_ip dest_port bytes app
12- Medición de la latencia de E/S de almacenamiento
Identifique rápidamente los cuellos de botella de E/S en sus sistemas.

index=main sourcetype=iostat
| timechart avg(latency) by host
13- Medición de la velocidad de almacenamiento y la utilización de E/S por parte del host
Es sencillo realizar un seguimiento de las operaciones de entrada/salida del disco, lo que le ayuda a descubrir rápidamente problemas de almacenamiento en sus servidores.

index=main sourcetype=iostat
| eval hostdevice=host+":"+Device
| timechart avg(total_ops) by hostdevice
14- Medición de la utilización de la memoria por parte del host
Con Splunk Enterprise es fácil realizar un seguimiento del uso de la memoria de sus sistemas.

index=main sourcetype=vmstat
| stats max(memUsedPct) as memused by host
| where memused>80
15- Detección de DNS fraudulentos
Busque solicitudes DNS que no estén destinadas al servidor DNS dedicado.

index=security sourcetype=cp_log src_ip!=192.168.14.10 dest_ip!=192.168.14.10
protocol=53 action!=Drop
| where dest_ip="192.168.0.0/16" AND src_ip="192.168.0.0/16"
| stats count, values(dest_ip) by src_ip
16- Comandos sospechosos de PowerShell
Busque registros con comandos que intenten descargar scripts/contenido externos o que intenten eludir PowerShell.

index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
AND ((ScriptBlockText=*-noni* *iex* *New-Object*) OR (ScriptBlockText=*-ep* *bypass* *-Enc*) OR
(ScriptBlockText=*powershell* *reg* *add*
*HKCU\\software\\microsoft\\windows\\currentversion\\run*) OR (ScriptBlockText=*bypass* *-
noprofile* *-windowstyle* *hidden* *new-object* *system.net.webclient* *.download*) OR
(ScriptBlockText=*iex* *New-Object* *Net.WebClient* *.Download*))
| table Computer, ScriptBlockText, UserID
17- Se borró el registro de auditoría de Windows
Busque registros de seguridad filtrados con el código de evento 1102.

index=windows source="WinEventLog:Security" EventCode=1102
| table _time, host, signature, user
18- Detección de escaneo de red y puertos
Busque un recuento distinto de puertos de destino en un corto período de tiempo.

| from datamodel:"Network_Traffic"."All_Traffic"
| stats dc(dest_port) as dc_dest_port by src, dest
| where dc_dest_port > 10
O

index=__your_sysmon_index__ sourcetype=firewall*
| stats dc(dest_port) as num_dest_port dc(dest_ip) as num_dest_ip by src_ip
| where num_dest_port >500 OR num_dest_ip >500
19- Acceso inusual
Busque el número de intentos de inicio de sesión fallidos múltiples donde el inicio de sesión fue exitoso.

| from datamodel:"Authentication"."Authentication"
| where like(app,"ssh")
| stats list(action) as Attempts, count(eval(match(action,"failure"))) as Failed,
count(eval(match(action,"success"))) as Success by user,src,dest,app
| where mvcount(Attempts)>=6 AND Success>0 AND Failed>=5
20- Ataque de malware
Busque el número de infecciones del ataque de malware.

| from datamodel:"Malware"."Malware_Attacks"
| stats dc("signature") as "infection_count" by "dest"
| where 'infection_count'>1
21-Intento de agregar certificado a un almacén no confiable
Los atacantes pueden añadir su propio certificado raíz al almacén de certificados para que el navegador web confíe en él y no muestre una advertencia de seguridad al encontrar un certificado desconocido. Esta acción puede ser el preludio de actividades maliciosas.

| tstats count min(_time) as firstTime values(Processes.process) as process max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=*certutil* (Processes.process=*-addstore*) by Processes.parent_process Processes.process_name Processes.user
22 - Escritura de archivo por lotes en System32
Si bien los archivos por lotes no son inherentemente maliciosos, es poco común verlos creados después de la instalación del sistema operativo, especialmente en el directorio de Windows. Este análisis busca actividad sospechosa relacionada con la creación de archivos por lotes dentro del árbol de directorios C:\Windows\System32. Solo se producirán falsos positivos ocasionalmente debido a acciones del administrador.

| tstats count min(_time) as firstTime max(_time) as lastTime values(Filesystem.dest) as dest values(Filesystem.file_name) as file_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem by Filesystem.file_path   | rex field=file_name "(?<file_extension>\.[^\.]+)$" | search file_path=*system32* AND file_extension=.bat
23- Modificación de recuperación de fallos de BCDEdit
Esta búsqueda detecta las modificaciones que se le pasan a bcdedit.exe en las configuraciones de arranque de recuperación de errores integradas de Windows. El ransomware suele utilizar esta técnica para impedir la recuperación.

| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = bcdedit.exe Processes.process="*recoveryenabled*" (Processes.process="* no*") by Processes.process_name Processes.process Processes.parent_process_name Processes.dest Processes.user
24- Persistencia de trabajos BITS
La siguiente consulta identifica la utilidad Microsoft Background Intelligent Transfer Service (  bitsadmin.exe BITS) que programa un trabajo BITS para que persista en un punto final. La consulta identifica los parámetros utilizados para crear, reanudar o agregar un archivo a un trabajo BITS. Normalmente se ven combinados en una sola línea o se ejecutan en secuencia. Si se identifica, revise el trabajo BITS creado y capture cualquier archivo escrito en el disco. Es posible que BITS se utilice para cargar archivos, lo que puede requerir un análisis de datos de red adicional para su identificación. Puede utilizar esta función  bitsadmin /list /verbose para listar los trabajos durante la investigación.

| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=bitsadmin.exe Processes.process IN (*create*, *addfile*, *setnotifyflags*, *setnotifycmdline*, *setminretrydelay*, *setcustomheaders*, *resume* ) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
25- BITSAdmin Descargar archivo
La siguiente consulta identifica la utilidad Microsoft Background Intelligent Transfer Service  bitsadmin.exe que utiliza el  transfer parámetro para descargar un objeto remoto. Además, busque  download o  upload en la línea de comandos, los modificadores no son necesarios para realizar una transferencia. Capture cualquier archivo descargado. Revise la reputación de la IP o dominio utilizado. Normalmente, una vez ejecutado, se utilizará un comando posterior para ejecutar el archivo descargado. Tenga en cuenta que los eventos de conexión de red o modificación de archivos relacionados no se generarán ni crearán desde  bitsadmin.exe, pero los artefactos aparecerán en un proceso paralelo de  svchost.exe con una línea de comandos similar a  svchost.exe -k netsvcs -s BITS. Es importante revisar todos los procesos paralelos y secundarios para capturar cualquier comportamiento y artefacto. En algunos casos sospechosos y maliciosos, se crearán trabajos de BITS. Puede utilizar  bitsadmin /list /verbose para listar los trabajos durante la investigación.

| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=bitsadmin.exe Processes.process=*transfer* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
26- Descarga de CertUtil con URLCache y argumentos divididos
Certutil.exe puede descargar un archivo desde un destino remoto usando  urlcache. Este comportamiento requiere que se pase una URL en la línea de comandos. Además,   se usarán  f (force) y  (Dividir elementos ASN.1 incrustados y guardarlos en archivos). No es del todo común que  contacte con el espacio de IP públicas. Sin embargo, es poco común que   escriba archivos en rutas de escritura públicas.\ Durante el triaje, capture cualquier archivo en el disco y revíselo. Revise la reputación de la IP remota o dominio en cuestión.splitcertutil.execertutil.exe

| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=certutil.exe Processes.process=*urlcache* Processes.process=*split* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
27- Descarga de CertUtil con VerifyCtl y argumentos divididos
Certutil.exe puede descargar un archivo desde un destino remoto usando  VerifyCtl. Este comportamiento requiere que se pase una URL en la línea de comandos. Además,   se usarán  f (force) y  (Dividir elementos ASN.1 incrustados y guardarlos en archivos). No es del todo común que  contacte con el espacio de IP públicas. \ Durante el triaje, capture cualquier archivo en el disco y revíselo. Revise la reputación de la IP remota o dominio en cuestión. Usando  , el archivo se escribirá en el directorio de trabajo actual o  .splitcertutil.exeVerifyCtl%APPDATA%\..\LocalLow\Microsoft\CryptnetUrlCache\Content\<hash>

| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=certutil.exe Processes.process=*verifyctl* Processes.process=*split* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
28- Extracción de certificados con Certutil.exe
Esta búsqueda busca argumentos para certutil.exe que indiquen la manipulación o extracción del certificado. Este certificado se puede usar para firmar nuevos tokens de autenticación, especialmente en entornos federados como Windows ADFS.

| tstats count min(_time) as firstTime values(Processes.process) as process max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=certutil.exe Processes.process = "* -exportPFX *" by Processes.parent_process Processes.process_name Processes.process Processes.user
29- CertUtil con argumento Decode
CertUtil.exe puede usarse para  encode decodificar  decode un archivo, incluyendo código PE y de script. La codificación convertirá un archivo a base64 con  etiquetas ----BEGIN CERTIFICATE----- y  ----END CERTIFICATE----- . El uso malicioso incluirá la decodificación de un archivo codificado que se haya descargado. Una vez decodificado, será cargado por un proceso paralelo. Tenga en cuenta que hay dos parámetros de comando adicionales que pueden usarse:  encodehex y  decodehex. De manera similar, el archivo se codificará en HEX y luego se decodificará para su posterior ejecución. Durante el análisis, identifique el origen del archivo que se está decodificando. Revise su contenido o comportamiento de ejecución para un análisis más profundo.

| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=certutil.exe Processes.process=*decode* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
30- Crear cuentas de administrador local usando net.exe
Esta búsqueda busca la creación de cuentas de administrador local mediante net.exe.

| tstats count values(Processes.user) as user values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=net.exe OR Processes.process_name=net1.exe) AND (Processes.process=*localgroup* OR Processes.process=*/add* OR Processes.process=*user*) by Processes.process Processes.process_name Processes.dest   |`create_local_admin_accounts_using_net_exe_filter`
31- Crear un hilo remoto en LSASS
Los atacantes pueden crear un hilo remoto en el servicio LSASS como parte de un flujo de trabajo para extraer credenciales.

`sysmon` EventID=8 TargetImage=*lsass.exe | stats count min(_time) as firstTime max(_time) as lastTime by Computer, EventCode, TargetImage, TargetProcessId | rename Computer as dest
32- Crear servicio en una ruta de archivo sospechosa
Esta detección sirve para identificar la creación de un "servicio en modo de usuario" cuya ruta de archivo se encuentra en una carpeta de servicios no común en Windows.

`wineventlog_system` EventCode=7045  Service_File_Name = "*\.exe" NOT (Service_File_Name IN ("C:\\Windows\\*", "C:\\Program File*", "C:\\Programdata\\*", "%systemroot%\\*")) Service_Type = "user mode service" | stats count min(_time) as firstTime max(_time) as lastTime by EventCode Service_File_Name Service_Name Service_Start_Type Service_Type
33- Enmascaramiento de procesos comunes de Windows
El enmascaramiento se produce cuando el nombre o la ubicación de un objeto, legítimo o malicioso, se manipula o se utiliza indebidamente para evadir las defensas y la vigilancia. Esto puede incluir la manipulación de los metadatos de los archivos, el engaño a los usuarios para que identifiquen erróneamente el tipo de archivo y el uso de nombres legítimos de tareas o servicios.

Los autores de malware suelen utilizar esta técnica para ocultar ejecutables maliciosos detrás de nombres de ejecutables legítimos de Windows (por ejemplo  lsass.exe,  svchost.exe, , etc.).

index=__your_sysmon_index__ source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND (
(process_name=svchost.exe AND NOT (process_path="C:\\Windows\\System32\\svchost.exe" OR process_path="C:\\Windows\\SysWow64\\svchost.exe"))
OR (process_name=smss.exe AND NOT process_path="C:\\Windows\\System32\\smss.exe")
OR (process_name=wininit.exe AND NOT process_path="C:\\Windows\\System32\\wininit.exe")
OR (process_name=taskhost.exe AND NOT process_path="C:\\Windows\\System32\\taskhost.exe")
OR (process_name=lasass.exe AND NOT process_path="C:\\Windows\\System32\\lsass.exe")
OR (process_name=winlogon.exe AND NOT process_path="C:\\Windows\\System32\\winlogon.exe")
OR (process_name=csrss.exe AND NOT process_path="C:\\Windows\\System32\\csrss.exe")
OR (process_name=services.exe AND NOT process_path="C:\\Windows\\System32\\services.exe")
OR (process_name=lsm.exe AND NOT process_path="C:\\Windows\\System32\\lsm.exe")
OR (process_name=explorer.exe AND NOT process_path="C:\\Windows\\explorer.exe")
)
34- Proceso hijo inusual generado mediante una vulnerabilidad DDE.
Los atacantes pueden usar el Intercambio Dinámico de Datos (DDE) de Windows para ejecutar comandos arbitrarios. DDE es un protocolo cliente-servidor para la comunicación entre procesos (IPC) puntual o continua entre aplicaciones. Una vez establecida la conexión, las aplicaciones pueden intercambiar de forma autónoma transacciones que consisten en cadenas de texto, enlaces de datos activos (notificaciones cuando cambia un elemento de datos), enlaces de datos duplicados (duplicados de cambios en un elemento de datos) y solicitudes de ejecución de comandos.

index = __your_sysmon__index__ (ParentImage="*excel.exe" OR ParentImage="*word.exe" OR ParentImage="*outlook.exe") Image="*.exe"
35- Detección de manipulación del símbolo del sistema de Windows Defender
En un intento por evitar ser detectados tras comprometer un equipo, los ciberdelincuentes suelen intentar deshabilitar Windows Defender. Esto se suele hacer mediante «sc» (control de servicios), una herramienta legítima de Microsoft para la gestión de servicios. Esta acción interfiere con la detección de eventos y puede provocar que un incidente de seguridad pase desapercibido, lo que podría derivar en una mayor vulneración de la red.

index= __your_sysmon__index__ EventCode=1 Image = "C:\\Windows\\System32\\sc.exe"  | regex CommandLine="^sc\s*(config|stop|query)\sWinDefend$"
36- Deshabilitar UAC
Tras comprometer un equipo, los ciberdelincuentes suelen intentar desactivar el Control de cuentas de usuario (UAC) para escalar privilegios. Esto se suele lograr modificando la clave del registro de las directivas del sistema mediante "reg.exe", una herramienta legítima de Microsoft para modificar el registro a través de la línea de comandos o scripts. Esta acción interfiere con el UAC y puede permitir que el ciberdelincuente escale privilegios en el sistema comprometido, facilitando así una mayor explotación del mismo.

sourcetype = __your_sysmon_index__ ParentImage = "C:\\Windows\\System32\\cmd.exe" | where like(CommandLine,"reg.exe%HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System%REG_DWORD /d 0%")
37- Identificación de la actividad de escaneo de puertos
Tras comprometer una máquina inicial, los atacantes suelen intentar moverse lateralmente por la red. El primer paso para intentar este movimiento lateral suele consistir en realizar escaneos de identificación de host, puertos y servicios en la red interna a través de la máquina comprometida, utilizando herramientas como Nmap, Cobalt Strike, etc.

sourcetype='firewall_logs' dest_ip = 'internal_subnet' | stats dc(dest_port) as pcount by src_ip | where pcount >5
38- Cadenas de línea de comandos inusualmente largas
A menudo, tras obtener acceso a un sistema, un atacante intenta ejecutar algún tipo de malware para infectar aún más el equipo de la víctima. Este malware suele tener largas cadenas de comandos, lo que podría ser un indicador de ataque. En este caso, utilizamos Sysmon y Splunk para determinar la longitud promedio de las cadenas de comandos y buscar aquellas que se extienden a lo largo de varias líneas, identificando así anomalías y posibles comandos maliciosos.

index=__your_sysmon_index__ sourcetype="xmlwineventlog" EventCode=4688  |eval cmd_len=len(CommandLine) | eventstats avg(cmd_len) as avg by host| stats max(cmd_len) as maxlen, values(avg) as avgperhost by host, CommandLine | where maxlen > 10*avgperhost
39- Borrar los registros de Windows con Wevtutil
En un intento por borrar rastros tras comprometer un equipo, los ciberdelincuentes suelen intentar eliminar los registros de eventos de Windows. Esto se suele hacer mediante "wevtutil", una herramienta legítima de Microsoft. Esta acción interfiere con la recopilación y notificación de eventos, lo que puede provocar que un incidente de seguridad pase desapercibido y, por consiguiente, que la red se vea aún más comprometida.

index=__your_sysmon_index__ sourcetype= __your__windows__sysmon__sourcetype EventCode=1 Image=*wevtutil* CommandLine=*cl* (CommandLine=*System* OR CommandLine=*Security* OR CommandLine=*Setup* OR CommandLine=*Application*)
40- Proceso hijo inusual para Spoolsv.Exe o Connhost.Exe
Tras obtener acceso inicial a un sistema, los ciberdelincuentes intentan escalar privilegios, ya que pueden estar operando dentro de un proceso con privilegios inferiores que no les permite acceder a información protegida ni realizar tareas que requieren permisos más elevados. Una forma común de escalar privilegios en un sistema es mediante la invocación externa y la explotación de los ejecutables spoolsv o connhost, ambos aplicaciones legítimas de Windows. Esta consulta busca la invocación de cualquiera de estos ejecutables por parte de un usuario, lo que nos alerta sobre cualquier actividad potencialmente maliciosa.

(index=__your_sysmon_index__ EventCode=1) (Image=C:\\Windows\\System32\\spoolsv.exe* OR Image=C:\\Windows\\System32\\conhost.exe) ParentImage = "C:\\Windows\\System32\\cmd.exe"
41- Detección de eliminación de copias de instantáneas mediante Vssadmin.exe
Tras comprometer una red de sistemas, los ciberdelincuentes suelen intentar eliminar las copias de seguridad (Shadow Copy) para impedir que los administradores restauren los sistemas a versiones anteriores al ataque. Esto se suele hacer mediante vssadmin, una herramienta legítima de Windows para interactuar con las copias de seguridad. La falta de detección de esta técnica, empleada frecuentemente por variantes de ransomware como «Olympic Destroyer», puede provocar fallos en la recuperación de los sistemas tras un ataque.

index=__your_win_event_log_index__ EventType=4688 CommandLine:"delete" OriginalFileName:"VSSADMIN.EXE"
42- Webshell-Árbol de procesos indicativo
Un shell web es un script web alojado en un servidor web de acceso público que permite a un atacante utilizarlo como puerta de enlace en una red. Durante su funcionamiento, el shell envía comandos desde la aplicación web al sistema operativo del servidor. Este análisis busca ejecutables de enumeración de hosts iniciados por cualquier servicio web que normalmente no se ejecutaría en ese entorno.

index=__your_sysmon_index__ (ParentImage="C:\\Windows\\System32\\services.exe" Image="C:\\Windows\\System32\\cmd.exe" (CommandLine="*echo*" AND CommandLine="*\\pipe\\*"))
OR (Image="C:\\Windows\\System32\\rundll32.exe" CommandLine="*,a /p:*")
43- Obtener elevación del sistema
Los ciberdelincuentes suelen escalar privilegios a la cuenta SYSTEM tras acceder a un sistema Windows, lo que les permite realizar diversos ataques con mayor eficacia. Herramientas como Meterpreter, Cobalt Strike y Empire llevan a cabo pasos automatizados para "obtener acceso a SYSTEM", lo que equivale a cambiar a la cuenta de usuario SYSTEM. La mayoría de estas herramientas utilizan varias técnicas para intentar alcanzar SYSTEM: en la primera, crean una tubería con nombre y conectan una instancia de cmd.exe a ella, lo que les permite suplantar el contexto de seguridad de cmd.exe, que es SYSTEM. En la segunda, se inyecta una DLL maliciosa en un proceso que se ejecuta como SYSTEM; la DLL inyectada roba el token de SYSTEM y lo aplica donde sea necesario para escalar privilegios. Este análisis busca ambas técnicas.

index=__your_sysmon_index__ (ParentImage="C:\\Windows\\System32\\services.exe" Image="C:\\Windows\\System32\\cmd.exe" (CommandLine="*echo*" AND CommandLine="*\\pipe\\*"))
OR (Image="C:\\Windows\\System32\\rundll32.exe" CommandLine="*,a /p:*")
index=__your_sysmon_index__ (Image="C:\\Windows\\System32\\cmd.exe" OR CommandLine="*%COMSPEC%*") (CommandLine="*echo*" AND CommandLine="*\pipe\*")
44- Scripts de inicialización de arranque o inicio de sesión
Los atacantes pueden programar la ejecución de software cada vez que un usuario inicia sesión en el sistema; esto se hace para establecer persistencia y, a veces, para el movimiento lateral. Este desencadenante se establece a través de la clave de registro HKEY_CURRENT_USER\Environment UserInitMprLogonScript . Esta firma detecta modificaciones en claves existentes o la creación de nuevas claves en esa ruta. Si los usuarios añaden scripts inofensivos a esta ruta de forma intencionada, se producirán falsos positivos; sin embargo, este caso es poco frecuente. Existen otras formas de ejecutar un script al inicio o al iniciar sesión que no están contempladas en esta firma. Cabe destacar que esta firma coincide con la herramienta Autoruns de Windows Sysinternals, que también detectaría cambios en esta ruta del registro.

(index=__your_sysmon_index__ EventCode=1 Image="C:\\Windows\\System32\\reg.exe" CommandLine="*add*\\Environment*UserInitMprLogonScript") OR (index=__your_sysmon_index__ (EventCode=12 OR EventCode=14 OR EventCode=13) TargetObject="*\\Environment*UserInitMprLogonScript")
45- Análisis de la red local
Los atacantes pueden usar diversas herramientas para obtener visibilidad sobre el estado actual de la red: qué procesos escuchan en qué puertos, qué servicios se ejecutan en otros hosts, etc. Este análisis busca los nombres de las herramientas de análisis de red más comunes. Si bien esto puede generar ruido en redes donde los administradores de sistemas usan estas herramientas con regularidad, en la mayoría de las redes su uso es significativo.

(index=__your_sysmon_index__ EventCode=1) (Image="*tshark.exe" OR Image="*windump.exe" OR (Image="*logman.exe" AND ParentImage!="?" AND ParentImage!="C:\\Program Files\\Windows Event Reporting\\Core\\EventReporting.AgentService.exe") OR Image="*tcpdump.exe" OR Image="*wprui.exe" OR Image="*wpr.exe")
46- Inyección de DLL con Mavinject
Inyectar una DLL maliciosa en un proceso es una táctica común de los atacantes. Si bien existen numerosas formas de hacerlo, mavinject.exe es una herramienta de uso frecuente, ya que integra muchos de los pasos necesarios en uno solo y está disponible en Windows. Los atacantes pueden cambiar el nombre del ejecutable, por lo que también utilizamos el argumento común "INJECTRUNNING" como firma relacionada. Puede ser necesario incluir ciertas aplicaciones en la lista blanca para reducir el ruido en este análisis.

(index=__your_sysmon_index__ EventCode=1) (Image="C:\\Windows\\SysWOW64\\mavinject.exe" OR Image="C:\\Windows\\System32\\mavinject.exe" OR CommandLine="*\INJECTRUNNING*")
47- Procesos iniciados a partir de un padre irregular
Los atacantes pueden iniciar procesos legítimos y luego usar su memoria para ejecutar código malicioso. Este análisis busca procesos comunes de Windows que se hayan utilizado de esta manera en el pasado; cuando se inician con este propósito, es posible que no tengan el proceso padre estándar que cabría esperar. Esta lista no es exhaustiva y los ciberdelincuentes pueden eludir esta discrepancia. Estas firmas solo funcionan si Sysmon informa sobre el proceso padre, lo cual no siempre ocurre si el proceso padre finaliza antes de que Sysmon procese el evento.

(index=__your_sysmon_index__ EventCode=1) AND ParentImage!="?" AND ParentImage!="C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-regmon.exe" AND ParentImage!="C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunk-powershell.exe" AND
((Image="C:\\Windows\System32\\smss.exe" AND (ParentImage!="C:\\Windows\\System32\\smss.exe" AND ParentImage!="System")) OR
(Image="C:\\Windows\\System32\\csrss.exe" AND (ParentImage!="C:\\Windows\\System32\\smss.exe" AND ParentImage!="C:\\Windows\\System32\\svchost.exe")) OR
(Image="C:\\Windows\\System32\\wininit.exe" AND ParentImage!="C:\\Windows\\System32\\smss.exe") OR
(Image="C:\\Windows\\System32\\winlogon.exe" AND ParentImage!="C:\\Windows\\System32\\smss.exe") OR
(Image="C:\\Windows\\System32\\lsass.exe" and ParentImage!="C:\\Windows\\System32\\wininit.exe") OR
(Image="C:\\Windows\\System32\\LogonUI.exe" AND (ParentImage!="C:\\Windows\\System32\\winlogon.exe" AND ParentImage!="C:\\Windows\\System32\\wininit.exe")) OR
(Image="C:\\Windows\\System32\\services.exe" AND ParentImage!="C:\\Windows\\System32\\wininit.exe") OR
(Image="C:\\Windows\\System32\\spoolsv.exe" AND ParentImage!="C:\\Windows\\System32\\services.exe") OR
(Image="C:\\Windows\\System32\\taskhost.exe" AND (ParentImage!="C:\\Windows\\System32\\services.exe" AND ParentImage!="C:\\Windows\\System32\\svchost.exe")) OR
(Image="C:\\Windows\\System32\\taskhostw.exe" AND (ParentImage!="C:\\Windows\\System32\\services.exe" AND ParentImage!="C:\\Windows\\System32\\svchost.exe")) OR
(Image="C:\\Windows\System32\\userinit.exe" AND (ParentImage!="C:\\Windows\\System32\\dwm.exe" AND ParentImage!="C:\\Windows\\System32\\winlogon.exe")))
48- Borrar el historial de comandos de la consola de PowerShell
Los atacantes pueden intentar ocultar sus huellas eliminando el historial de comandos ejecutados en la consola de PowerShell o desactivando el guardado del historial. Este análisis busca varios comandos que realicen esta acción. No se registran los eventos que se ejecutan dentro de la consola; solo se detectan los comandos de línea de comandos. Tenga en cuenta que el comando para eliminar directamente el archivo de historial puede variar ligeramente si este no se guarda en la ruta predeterminada del sistema.

(index=__your_sysmon_index__ EventCode=1) (CommandLine="*rm (Get-PSReadlineOption).HistorySavePath*" OR CommandLine="*del (Get-PSReadlineOption).HistorySavePath*" OR CommandLine="*Set-PSReadlineOption –HistorySaveStyle SaveNothing*" OR CommandLine="*Remove-Item (Get-PSReadlineOption).HistorySavePath*" OR CommandLine="del*Microsoft\\Windows\\Powershell\\PSReadline\\ConsoleHost_history.txt")
49- Descubrimiento del grupo de permisos locales
Los ciberdelincuentes suelen enumerar los grupos de permisos locales o de dominio. La utilidad net se usa habitualmente para este fin. Este análisis busca instancias de net.exe, que normalmente no se usa con fines benignos, aunque las acciones del administrador del sistema pueden generar falsos positivos.

(index=__your_sysmon_index__ EventCode=1) Image="C:\\Windows\\System32\\net.exe" AND (CommandLine="* user*" OR CommandLine="* group*" OR CommandLine="* localgroup*" OR CommandLine="*get-localgroup*" OR CommandLine="*get-ADPrincipalGroupMembership*")
50- Eliminación de la conexión de recurso compartido de red
Los adversarios pueden usar recursos compartidos de red para filtrar datos; luego los eliminarán para borrar sus huellas. Este análisis busca la eliminación de recursos compartidos de red mediante la línea de comandos, lo cual es un evento poco común.

(index=__your_sysmon_index__ EventCode=1) ((Image="C:\\Windows\\System32\\net.exe" AND CommandLine="*delete*") OR CommandLine="*Remove-SmbShare*" OR CommandLine="*Remove-FileShare*")
51- MSBuild y msxsl
Las utilidades de desarrollo de confianza, como MSBuild, pueden utilizarse para ejecutar código malicioso con privilegios elevados. Este análisis busca instancias de msbuild.exe, que ejecuta cualquier código C# dentro de un documento XML; y msxsl.exe, que procesa las especificaciones de transformación XSL para archivos XML y ejecuta diversos lenguajes de scripting contenidos en el archivo XSL. Ambos ejecutables rara vez se utilizan fuera de Visual Studio.

(index=__your_sysmon_index__ EventCode=1) (Image="C:\\Program Files (x86)\\Microsoft Visual Studio\\*\\bin\\MSBuild.exe" OR Image="C:\\Windows\\Microsoft.NET\\Framework*\\msbuild.exe" OR Image="C:\\users\\*\\appdata\\roaming\\microsoft\\msxsl.exe") ParentImage!="*\\Microsoft Visual Studio*")
52- Acceso HTML compilado
Los atacantes pueden ocultar código malicioso en archivos HTML compilados con la extensión .chm. Al leer estos archivos, Windows utiliza el ejecutable de ayuda HTML llamado hh.exe, que es la firma de este análisis.

(index=__your_sysmon_index__ EventCode=1) (Image="C:\\Windows\\syswow64\\hh.exe" OR Image="C:\\Windows\\system32\\hh.exe")
53- CMSTP
CMSTP.exe es el instalador de perfiles del Administrador de conexiones de Microsoft, que puede utilizarse para configurar oyentes que reciban e instalen malware desde fuentes remotas de forma segura. Cuando se detecta CMSTP.exe junto con una conexión externa, es un buen indicio de esta táctica.

(index=__your_sysmon_index__ EventCode=3) Image="C:\\Windows\\System32\\CMSTP.exe" | where ((!cidrmatch("10.0.0.0/8", SourceIp) AND !cidrmatch("192.168.0.0/16", SourceIp) AND !cidrmatch("172.16.0.0/12", SourceIp))
54- Edición del registro desde el protector de pantalla
Los atacantes pueden usar archivos de salvapantallas para ejecutar código malicioso. Este análisis se activa ante modificaciones sospechosas en las claves de registro del salvapantallas, que determinan qué archivo .scr ejecuta el salvapantallas.

index=your_sysmon_index (EventCode=12 OR EventCode=13 OR EventCode=14) TargetObject="*\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\SCRNSAVE.EXE"
55- Tarea programada - Acceso a archivos
Para lograr persistencia, escalada de privilegios o ejecución remota, un atacante puede usar el Programador de tareas de Windows para programar la ejecución de un comando en una fecha, hora e incluso host específicos. El Programador de tareas almacena las tareas como archivos en dos ubicaciones: C:\Windows\Tasks (versión anterior) o C:\Windows\System32\Tasks. Por lo tanto, este análisis busca la creación de archivos de tareas en estas dos ubicaciones.

index=__your_sysmon_index__ EventCode=11 Image!="C:\\WINDOWS\\system32\\svchost.exe" (TargetFilename="C:\\Windows\\System32\\Tasks\\*" OR TargetFilename="C:\\Windows\\Tasks\\*")
56- Secuestro del modelo de objetos de componentes
Los atacantes pueden lograr persistencia o escalar privilegios ejecutando contenido malicioso activado por referencias secuestradas a objetos del Modelo de Objetos de Componentes (COM). Esto generalmente se realiza reemplazando las entradas del registro de objetos COM en las claves HKEY_CURRENT_USER\Software\Classes\CLSID o HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID. Por lo tanto, este análisis busca cualquier cambio en estas claves.

index=__your_sysmon_index__ (EventCode=12 OR EventCode=13 OR EventCode=14) TargetObject="*\\Software\\Classes\\CLSID\\*"
57- Bloqueo del indicador - Conductor descargado
Los atacantes pueden intentar eludir las defensas del sistema descargando los controladores de minifiltro utilizados por sensores locales como Sysmon mediante la utilidad de línea de comandos fltmc. Por lo tanto, este análisis busca invocaciones de esta utilidad en la línea de comandos cuando se utiliza para descargar los controladores de minifiltro.

index=client EventCode=1 CommandLine="*unload*" (Image="C:\\Windows\\SysWOW64\\fltMC.exe" OR Image="C:\\Windows\\System32\\fltMC.exe")
58- Credenciales en archivos y registro
Los adversarios pueden buscar en el Registro de Windows en sistemas comprometidos credenciales almacenadas de forma insegura para obtener acceso a las mismas. Esto se puede lograr utilizando la funcionalidad de consulta de la utilidad del sistema reg.exe, buscando claves y valores que contengan cadenas como "password". Además, los adversarios pueden utilizar conjuntos de herramientas como PowerSploit con el fin de extraer credenciales de diversas aplicaciones como IIS. En consecuencia, este análisis busca invocaciones de reg.exe con esta función, así como de varios módulos de powersploit con funcionalidad similar.

((index=__your_sysmon_index__ EventCode=1) OR (index=__your_win_syslog_index__ EventCode=4688)) (CommandLine="*reg* query HKLM /f password /t REG_SZ /s*" OR CommandLine="reg* query HKCU /f password /t REG_SZ /s" OR CommandLine="*Get-UnattendedInstallFile*" OR CommandLine="*Get-Webconfig*" OR CommandLine="*Get-ApplicationHost*" OR CommandLine="*Get-SiteListPassword*" OR CommandLine="*Get-CachedGPPPassword*" OR CommandLine="*Get-RegistryAutoLogon*")
59- DLLs de AppInit
Los atacantes pueden establecer persistencia y/o elevar privilegios ejecutando contenido malicioso activado por las DLL de AppInit cargadas en los procesos. Las bibliotecas de vínculos dinámicos (DLL) especificadas en el valor AppInit_DLLs del Registro  HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows o  HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows cargadas por user32.dll en cada proceso que carga user32.dll pueden ser explotadas para obtener privilegios elevados al provocar que una DLL maliciosa se cargue y ejecute en el contexto de procesos independientes. Por consiguiente, este análisis busca modificaciones en estas claves del Registro que puedan indicar este tipo de abuso.

index=__your_sysmon_index__ (EventCode=12 OR EventCode=13 OR EventCode=14) (TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls\\*" OR TargetObject="*\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls\\*")
60- Ejecución de flujo de datos alternativo NTFS - Utilidades del sistema
Los flujos de datos alternativos (ADS) de NTFS pueden ser utilizados por atacantes para evadir las herramientas de seguridad mediante el almacenamiento de datos o binarios maliciosos en los metadatos de los atributos de los archivos. Los ADS también son potentes porque pueden ejecutarse directamente con diversas herramientas de Windows; por lo tanto, este análisis examina las formas comunes de ejecutar ADS utilizando utilidades del sistema como PowerShell.

NTFS ADS - PowerShell

index=__sysmon_index__ EventCode=1 Image=C:\\Windows\\*\\powershell.exe|regex CommandLine="Invoke-CimMethod\s+-ClassName\s+Win32_Process\s+-MethodName\s+Create.*\b(\w+(\.\w+)?):(\w+(\.\w+)?)|-ep bypass\s+-\s+<.*\b(\w+(\.\w+)?):(\w+(\.\w+)?)|-command.*Get-Content.*-Stream.*Set-Content.*start-process .*(\w+(\.\w+)?)"NTFS ADS - wmic
NTFS ADS - wmic

index=__sysmon_index__ EventCode=1 Image=C:\\Windows\\*\\wmic.exe | regex CommandLine="process call create.*\"(\w+(\.\w+)?):(\w+(\.\w+)?)"
NTFS ADS - rundll32

index=__sysmon_index__  EventCode=1 Image=C:\\Windows\\*\\rundll32.exe | regex CommandLine="\"?(\w+(\.\w+)?):(\w+(\.\w+)?)?\"?,\w+\|(advpack\.dll\|ieadvpack\.dll),RegisterOCX\s+(\w+\.\w+):(\w+(\.\w+)?)\|(shdocvw\.dll\|ieframe\.dll),OpenURL.*(\w+\.\w+):(\w+(\.\w+)?)"
NTFS ADS - wscript/cscript

index=__sysmon_index__ EventCode=1 (Image=C:\\Windows\\*\\wscript.exe OR Image=C:\\Windows\\*\\cscript.exe) | regex CommandLine="(?<!\/)\b\w+(\.\w+)?:\w+(\.\w+)?$"
61- Ejecución de flujo de datos alternativo NTFS - LOLBAS
Los flujos de datos alternativos (ADS) de NTFS pueden ser utilizados por atacantes para evadir las herramientas de seguridad mediante el almacenamiento de datos o binarios maliciosos en los metadatos de los atributos de los archivos. Los ADS también son potentes porque su contenido puede ejecutarse directamente mediante diversas herramientas de Windows; por consiguiente, este análisis examina las formas comunes de ejecutar ADS utilizando binarios y scripts de acceso no autorizado (LOLBAS).

NTFS ADS - control

index=__sysmon_index__ EventCode=1 (Image=C:\\Windows\System32\\control.exe OR Image=C:\\Windows\SysWOW64\\control.exe) | regex CommandLine="(\w+(\.\w+)?):(\w+\.dll)"
NTFS ADS - appvlp

index=__sysmon_index__ EventCode=1 (Image="C:\\Program Files\\Microsoft Office\\root\\Client\\AppVLP.exe" OR Image="C:\\Program Files (x86)\\Microsoft Office\\root\\Client\\AppVLP.exe") | regex CommandLine="(\w+(\.\w+)?):(\w+(\.\w+)?)"
NTFS ADS - cmd

index=__sysmon_index__ EventCode=1 (Image=C:\\Windows\\System32\\cmd.exe OR Image=C:\\Windows\\SysWOW64\\cmd.exe) | regex CommandLine="-\s+<.*\b(\w+(\.\w+)?):(\w+(\.\w+)?)"
NTFS ADS - ftp

index=__sysmon_index__ EventCode=1 (Image=C:\\Windows\\System32\\ftp.exe OR Image=C:\\Windows\\SysWOW64\\ftp.exe) | regex CommandLine="-s:(\w+(\.\w+)?):(\w+(\.\w+)?)"
NTFS ADS - bash

index=__sysmon_index__ EventCode=1 (Image=C:\\Windows\\System32\\bash.exe OR C:\\Windows\\SysWOW64\\bash.exe) | regex CommandLine="-c.*(\w+(\.\w+)?):(\w+(\.\w+)?)"
NTFS ADS - mavinject

index=__sysmon_index__ EventCode=1 (Image=C:\\Windows\\System32\\mavinject.exe OR C:\\Windows\\SysWOW64\\mavinject.exe) | regex CommandLine="\d+\s+\/INJECTRUNNING.*\b(\w+(\.\w+)?):(\w+(\.\w+)?)"
NTFS ADS - bitsadmin

index=__sysmon_index__ EventCode=1 (Image=C:\\Windows\\System32\\bitsadmin.exe OR C:\\Windows\\SysWOW64\\bitsadmin.exe) | regex CommandLine="\/create.*\/addfile.*\/SetNotifyCmdLine.*\b(\w+\.\w+):(\w+(\.\w+)?)"
62- Ejecución con AT
Para obtener persistencia, escalada de privilegios, o ejecución remota, un adversario puede usar el comando integrado de Windows AT (at.exe) para programar un comando para ser ejecutado en una hora, fecha e incluso host específicos. Este método ha sido utilizado tanto por adversarios como por administradores. Su uso puede conducir a la detección de hosts comprometidos y usuarios comprometidos si se utiliza para moverse lateralmente. La herramienta integrada de Windows schtasks.exe (CAR-2013-08-001Ofrece mayor flexibilidad al crear, modificar y enumerar tareas. Por estas razones, schtasks.exe es más utilizado por administradores, herramientas/scripts y usuarios avanzados.

index=__your_sysmon_index__ Image="C:\\Windows\\*\\at.exe"|stats values(CommandLine) as "Command Lines" by ComputerName
63- Ejecutar archivos ejecutables con el mismo hash y nombres diferentes.
Los ejecutables generalmente no se renombran, por lo que un hash dado de un ejecutable solo debería tener un nombre. Identificar instancias donde varios nombres de procesos comparten el mismo hash puede encontrar casos donde los atacantes copian herramientas a diferentes carpetas o hosts. evitar ser detectado.

Aunque este análisis se basó inicialmente en hashes MD5, es igualmente aplicable a cualquier convención de hash.

index=__your_sysmon_index__ EventCode=1|stats dc(Hashes) as Num_Hashes values(Hashes) as "Hashes" by Image|where Num_Hashes > 1
64- Argumentos sospechosos
Los actores maliciosos pueden cambiar el nombre de los comandos integrados o de las herramientas externas, como las proporcionadas por SysInternals, para ser más fáciles de usar. mezclarse con con el entorno. En esos casos, la ruta del archivo es arbitraria y puede mimetizarse con el fondo. Si se examinan detenidamente los argumentos, es posible inferir qué herramientas se están ejecutando y comprender las acciones del atacante. Cuando un software legítimo comparte las mismas líneas de comando, debe incluirse en la lista blanca según los parámetros esperados.

index=__your_sysmon_index__ EventCode=1 (CommandLine="* -R * -pw*" OR CommandLine="* -pw * *@*" OR CommandLine="*sekurlsa*" OR CommandLine="* -hp *" OR CommandLine="* a *")
65- Monitoreo de la actividad de inicio de sesión del usuario
La monitorización de los eventos de inicio y cierre de sesión de los hosts en la red es fundamental para tener una visión general de la situación. Esta información puede utilizarse como indicador de actividad inusual, así como para corroborar la actividad observada en otros lugares.

Puede aplicarse a diversos tipos de monitorización, según la información que se desee obtener. Algunos casos de uso incluyen la monitorización de todas las conexiones remotas y la creación de cronogramas de inicio de sesión para los usuarios. Los eventos de inicio de sesión corresponden al código de evento de Windows 4624 para Windows Vista y versiones posteriores, y al 518 para versiones anteriores a Vista. Los eventos de cierre de sesión corresponden al código 4634 para Windows Vista y versiones posteriores, y al 538 para versiones anteriores a Vista.

index=__your_win_event_log_index__ EventCode=4624|search NOT [search index=__your_win_event_log_index__ EventCode=4624|top 30 Account_Name|table Account_Name]
66- Ejecución de PowerShell
PowerShell PowerShell es un entorno de scripting incluido en Windows que utilizan tanto atacantes como administradores. La ejecución de scripts de PowerShell en la mayoría de las versiones de Windows es opaca y no suele estar protegida por antivirus, lo que facilita el uso de PowerShell para eludir las medidas de seguridad. Este análisis detecta la ejecución de scripts de PowerShell.

PowerShell se puede utilizar para ocultar la ejecución de comandos de línea supervisados, como por ejemplo:

net use
sc start
index=__your_sysmon_index__ EventCode=1 Image="C:\\Windows\\*\\powershell.exe" ParentImage!="C:\\Windows\\explorer.exe"|stats values(CommandLine) as "Command Lines" values(ParentImage) as "Parent Images" by ComputerName
67- Servicios lanzando Cmd
Windows ejecuta el Administrador de control de servicios (SCM) dentro del proceso  services.exe. Windows inicia los servicios como procesos independientes o cargas DLL dentro de un svchost.exe grupo. Para ser un servicio legítimo, un proceso (o DLL) debe tener el punto de entrada de servicio apropiado. Servicio principalSi una aplicación no tiene el punto de entrada, se agotará el tiempo de espera (el valor predeterminado es de 30 segundos) y el proceso se terminará.

Para sobrevivir al tiempo fuera, adversarios y equipos rojos Se pueden crear servicios que se dirigen  cmd.exe con el indicador  /c, seguido del comando deseado. El  /c indicador hace que el intérprete de comandos ejecute un comando y salga inmediatamente. Como resultado, el programa deseado permanecerá en ejecución e informará de un error al iniciar el servicio. Este análisis detectará la instancia del símbolo del sistema que se utiliza para lanzar el ejecutable malicioso real. Además, los procesos hijos y descendientes de services.exe se ejecutarán como usuario SYSTEM de forma predeterminada. Por lo tanto, los servicios son una forma conveniente para que un adversario obtenga Persistencia y Escalada de privilegios.

index=__your_sysmon_index__ EventCode=1 Image="C:\\Windows\\*\\cmd.exe" ParentImage="C:\\Windows\\*\\services.exe"
68- Comando ejecutado desde WinLogon
Un adversario puede usar características de accesibilidad (Facilidad de acceso), como StickyKeys o Utilman, para iniciar un shell de comandos desde la pantalla de inicio de sesión y obtener acceso al SISTEMA. Dado que un adversario no tiene acceso físico a la máquina, esta técnica debe ejecutarse dentro Escritorio remotoPara evitar que un adversario acceda a la pantalla de inicio de sesión sin autenticarse previamente, debe habilitarse la autenticación a nivel de red (NLA). Si se configura un depurador para una de las funciones de accesibilidad, este interceptará el inicio del proceso de la función y, en su lugar, ejecutará una nueva línea de comandos. Este análisis busca instancias de  cmd.exe o  powershell.exe iniciadas directamente desde el proceso de inicio de sesión  winlogon.exe. Debe utilizarse junto con CAR-2014-11-003, que detecta los programas de accesibilidad en la línea de comandos.

index=__your_sysmon_index__ EventCode=1 ParentImage="C:\\Windows\\*\\winlogon.exe" Image="C:\\Windows\\*\\cmd.exe"
69- Comandos de descubrimiento de host
Al ingresar a un host por primera vez, un adversario puede intentar descubrir Información sobre el host. Existen varios comandos integrados de Windows que se pueden usar para obtener información sobre las configuraciones de software, los usuarios activos, los administradores y la configuración de red. Estos comandos deben ser monitoreados para identificar cuándo un adversario está obteniendo información sobre el sistema y el entorno. La información devuelta puede afectar las decisiones que un adversario puede tomar cuando establecer la persistencia, privilegios crecientes, o moverse lateralmente.

Dado que estos comandos están integrados, es posible que usuarios avanzados o incluso usuarios normales los ejecuten con frecuencia. Por lo tanto, un análisis que examine esta información debería contar con listas blancas o negras bien definidas y considerar un enfoque de detección de anomalías, de modo que esta información pueda aprenderse de forma dinámica.

index=__your_sysmon_index__ EventCode=1 (Image="C:\\Windows\\*\\hostname.exe" OR Image="C:\\Windows\\*\\ipconfig.exe" OR Image="C:\\Windows\\*\\net.exe" OR Image="C:\\Windows\\*\\quser.exe" OR Image="C:\\Windows\\*\\qwinsta.exe" OR (Image="C:\\Windows\\*\\sc.exe" AND (CommandLine="* query *" OR CommandLine="* qc *")) OR Image="C:\\Windows\\*\\systeminfo.exe" OR Image="C:\\Windows\\*\\tasklist.exe" OR Image="C:\\Windows\\*\\whoami.exe")|stats values(Image) as "Images" values(CommandLine) as "Command Lines" by ComputerName
70- Crear proceso remoto a través de WMIC
Los adversarios pueden utilizar Instrumentación de administración de Windows (WMI) para moverse lateralmente, lanzando ejecutables de forma remota. El análisis CAR-2014-12-001 Describe cómo detectar estos procesos con la monitorización del tráfico de red y la monitorización de procesos en el host de destino. Sin embargo, si  wmic.exe se utiliza la utilidad de línea de comandos en el host de origen, también se puede detectar en un análisis. La línea de comandos en el host de origen se construye de la siguiente manera:  wmic.exe /node:"\<hostname\>" process call create "\<command line\>". También es posible conectarse mediante la dirección IP, en cuyo caso la cadena  "\<hostname\>" se vería así:  IP Address.

Aunque este análisis se creó después CAR-2014-12-001Es un enfoque mucho más sencillo (aunque más limitado). Los procesos se pueden crear de forma remota a través de WMI de otras maneras, como mediante un acceso API más directo o la utilidad integrada.

index=__your_sysmon_index__ EventCode=1 Image="C:\\Windows\\*\\wmic.exe" CommandLine="* process call create *"|search CommandLine="* /node:*"
71- Omisión de UAC
La elusión del control de cuentas de usuario (UAC Bypass) generalmente se realiza aprovechando un proceso del sistema que tiene privilegios de escalada automática. Este análisis busca detectar esos casos, tal como se describe en la documentación de código abierto. UACME herramienta.

index=_your_sysmon_index_ EventCode=1 IntegrityLevel=High|search (ParentCommandLine="\"c:\\windows\\system32\\dism.exe\"*""*.xml" AND Image!="c:\\users\\*\\appdata\\local\\temp\\*\\dismhost.exe") OR ParentImage=c:\\windows\\system32\\fodhelper.exe OR (CommandLine="\"c:\\windows\\system32\\wusa.exe\"*/quiet*" AND User!=NOT_TRANSLATED AND CurrentDirectory=c:\\windows\\system32\\ AND ParentImage!=c:\\windows\\explorer.exe) OR CommandLine="*.exe\"*cleanmgr.exe /autoclean*" OR (ParentImage="c:\\windows\\*dccw.exe" AND Image!="c:\\windows\\system32\\cttune.exe") OR Image="c:\\program files\\windows media player\\osk.exe" OR ParentImage="c:\\windows\\system32\\slui.exe"|eval PossibleTechniques=case(like(lower(ParentCommandLine),"%c:\\windows\\system32\\dism.exe%"), "UACME #23", like(lower(Image),"c:\\program files\\windows media player\\osk.exe"), "UACME #32", like(lower(ParentImage),"c:\\windows\\system32\\fodhelper.exe"),  "UACME #33", like(lower(CommandLine),"%.exe\"%cleanmgr.exe /autoclean%"), "UACME #34", like(lower(Image),"c:\\windows\\system32\\wusa.exe"), "UACME #36", like(lower(ParentImage),"c:\\windows\\%dccw.exe"), "UACME #37", like(lower(ParentImage),"c:\\windows\\system32\\slui.exe"), "UACME #45")
72- Regsvr32 genérico
Regsvr32 puede utilizarse para ejecutar código arbitrario en el contexto de un binario firmado por Windows, lo que permite eludir la lista blanca de aplicaciones. Este análisis busca usos sospechosos de la herramienta. Si bien no es probable que se obtengan millones de coincidencias, este uso se produce durante la actividad normal, por lo que sería necesario establecer una línea base para que este análisis genere alertas. Alternativamente, puede utilizarse para la búsqueda manual de DLL nuevas o anómalas.

index=__your_sysmon_data__ EventCode=1 regsvr32.exe | search ParentImage="*regsvr32.exe" AND Image!="*regsvr32.exe*"
73- Squiblydoo
Squiblydoo es un uso específico de regsvr32.dll para cargar un script COM directamente desde internet y ejecutarlo sin pasar por la lista blanca de la aplicación. Se puede detectar buscando ejecuciones de regsvr32.exe que carguen scrobj.dll (que ejecuta el script COM) o, si esto genera demasiadas interferencias, aquellas que también carguen contenido directamente a través de HTTP o HTTPS.

Squiblydoo fue descrito por primera vez por Casey Smith en Red Canary, aunque esa entrada de blog ya no está disponible.

index=__your_sysmon_events__ EventCode=1 regsvr32.exe scrobj.dll | search Image="*regsvr32.exe"
74- Volcado de credenciales vía Mimikatz
Los programas de extracción de credenciales como Mimikatz pueden cargarse en memoria y, desde allí, leer datos de otros procesos. Este análisis busca instancias donde los procesos solicitan permisos específicos para leer partes del proceso LSASS con el fin de detectar cuándo se produce la extracción de credenciales. Una debilidad es que todas las implementaciones actuales están sobreoptimizadas para detectar patrones de acceso comunes utilizados por Mimikatz.

index=__your_sysmon_data__ EventCode=10 
TargetImage="C:\\WINDOWS\\system32\\lsass.exe"
(GrantedAccess=0x1410 OR GrantedAccess=0x1010 OR GrantedAccess=0x1438 OR GrantedAccess=0x143a OR GrantedAccess=0x1418)
CallTrace="C:\\windows\\SYSTEM32\\ntdll.dll+*|C:\\windows\\System32\\KERNELBASE.dll+20edd|UNKNOWN(*)" 
| table _time hostname user SourceImage GrantedAccess
75- Modificación de permisos de acceso
En ocasiones, los adversarios modifican los permisos de acceso a los objetos a nivel del sistema operativo. Existen diversas motivaciones para esta acción: por motivos de persistencia, pueden impedir que ciertos archivos u objetos se modifiquen en los sistemas y, por lo tanto, otorgar permisos solo a los administradores; asimismo, pueden querer que los archivos sean accesibles con permisos más bajos.

index=__your_windows_security_log_index__ EventCode=4670 Object_Type="File" Security_ID!="NT AUTHORITY\\SYSTEM"
76- Volcado de proceso Lsass mediante Procdump
Volcado de proceso Es una utilidad de línea de comandos de sysinternals cuyo propósito principal es monitorear una aplicación en busca de picos de CPU y generar volcados de memoria durante un pico que un administrador o desarrollador puede usar para determinar la causa del pico.

ProcDump puede utilizarse para volcar el espacio de memoria de lsass.exe al disco y procesarlo con una herramienta de acceso a credenciales como Mimikatz. Para ello, se ejecuta procdump.exe como usuario con privilegios y se especifican las opciones de línea de comandos para que lsass.exe se guarde en un archivo con un nombre cualquiera.

index=__your_sysmon_index__ EventCode=1 Image="*\\procdump*.exe" CommandLine="*lsass*"
77- Extracción de credenciales mediante el Administrador de tareas de Windows
El Administrador de tareas de Windows puede utilizarse para volcar el espacio de memoria en  lsass.exe disco y procesarlo con una herramienta de acceso a credenciales como Mimikatz. Para ello, inicie el Administrador de tareas como usuario con privilegios, seleccione la opción correspondiente  lsass.exey haga clic en «Crear archivo de volcado». Esto guarda un archivo de volcado en disco con un nombre determinista que incluye el nombre del proceso del que se está volcando el archivo.

index=__your_sysmon_index__ EventCode=11 TargetFilename="*lsass*.dmp" Image="C:\\Windows\\*\\taskmgr.exe"
78- Volcado de Active Directory mediante NTDSUtil
La herramienta NTDSUtil permite volcar una base de datos de Microsoft Active Directory a un disco para su procesamiento con una herramienta de acceso a credenciales como Mimikatz. Para ello, se ejecuta  ntdsutil.exe como usuario con privilegios de administrador, especificando los argumentos de la línea de comandos para la creación de un medio de instalación sin conexión de Active Directory y la ruta de la carpeta. Este proceso creará una copia de la base de datos de Active Directory  ntds.diten la ruta de carpeta especificada.

index=__your_sysmon_index__ EventCode=11 TargetFilename="*ntds.dit" Image="*ntdsutil.exe"
79- Eliminación de copias de instantáneas
Las ventanas Servicio de instantáneas de volumen Es una función integrada del sistema operativo que se puede utilizar para crear copias de seguridad de archivos y volúmenes.

Los atacantes pueden eliminar estas copias de seguridad, generalmente mediante utilidades del sistema como vssadmin.exe o wmic.exe, para impedir la recuperación de archivos y datos. Esta técnica es utilizada habitualmente por el ransomware con este fin.

Vssadmin.exe eliminar sombras

index=__your_sysmon_index__ EventCode=1 Image="C:\\Windows\\System32\\vssadmin.exe" CommandLine="*delete shadows*"
Eliminar copia de sombra de WMIC

index=__your_sysmon_index__ EventCode=1 Image="C:\\Windows\\*\\wmic.exe" CommandLine="*shadowcopy delete*"
80- Minivolcado de LSASS
Este análisis detecta la variante de volcado de credenciales mediante minivolcado, donde un proceso abre lsass.exe para extraer credenciales utilizando la llamada a la API de Win32. MiniDumpWriteDumpHerramientas como SafetyKatz, SafetyDump, y Dumpert de flanco Esta variante se utiliza por defecto y puede ser detectada por este análisis, aunque tenga en cuenta que no todas las opciones para usar esas herramientas darán como resultado este comportamiento específico.

El análisis se basa en un Analítica Sigma Contribución de Samir Bousseaden y escrito en un Blog sobre MENASECBusca un rastro de llamadas que incluya dbghelp.dll o dbgcore.dll, que exportan las funciones/permisos relevantes para realizar el volcado. También detecta el uso del Administrador de tareas de Windows (taskmgr.exe) para volcar lsass, que se describe en CAR-2019-08-001En esta versión del análisis Sigma,  GrantedAccess no se incluye el filtro porque no parecía filtrar ningún falso positivo e introduce la posibilidad de evasión.

index=__your_sysmon_index__ EventCode=10 TargetImage="C:\\windows\\system32\\lsass.exe" (CallTrace="*dbghelp.dll*" OR CallTrace="*dbgcore.dll*")| table _time host SourceProcessId SourceImage
81- Líneas de comando raras de LolBAS
LoLBAS Se trata de binarios y scripts integrados en Windows, frecuentemente firmados por Microsoft, que podrían ser utilizados por un atacante. Algunos LoLBAS se usan muy raramente y podría ser posible configurar alertas cada vez que se utilicen (esto dependería del entorno), pero muchos otros son muy comunes y no se pueden configurar alertas fácilmente.

Este análisis toma todas las instancias de ejecución de LoLBAS y luego busca instancias de líneas de comando que no son normales en el entorno. Esto puede detectar atacantes (que generalmente necesitarán los binarios para un uso distinto al habitual), pero también puede generar falsos positivos.

Es necesario ajustar el análisis. El valor  1.5 en la consulta indica el número de desviaciones estándar que se deben buscar. Se puede aumentar para filtrar más ruido y disminuir para obtener más resultados. Esto significa que probablemente sea mejor usarlo como análisis de búsqueda cuando hay analistas supervisando la pantalla y pudiendo ajustar el análisis, ya que el umbral puede no ser estable por mucho tiempo.

index=__your_sysmon_index__ EventCode=1 (OriginalFileName = At.exe OR OriginalFileName = Atbroker.exe OR OriginalFileName = Bash.exe OR OriginalFileName = Bitsadmin.exe OR OriginalFileName = Certutil.exe OR OriginalFileName = Cmd.exe OR OriginalFileName = Cmdkey.exe OR OriginalFileName = Cmstp.exe OR OriginalFileName = Control.exe OR OriginalFileName = Csc.exe OR OriginalFileName = Cscript.exe OR OriginalFileName = Dfsvc.exe OR OriginalFileName = Diskshadow.exe OR OriginalFileName = Dnscmd.exe OR OriginalFileName = Esentutl.exe OR OriginalFileName = Eventvwr.exe OR OriginalFileName = Expand.exe OR OriginalFileName = Extexport.exe OR OriginalFileName = Extrac32.exe OR OriginalFileName = Findstr.exe OR OriginalFileName = Forfiles.exe OR OriginalFileName = Ftp.exe OR OriginalFileName = Gpscript.exe OR OriginalFileName = Hh.exe OR OriginalFileName = Ie4uinit.exe OR OriginalFileName = Ieexec.exe OR OriginalFileName = Infdefaultinstall.exe OR OriginalFileName = Installutil.exe OR OriginalFileName = Jsc.exe OR OriginalFileName = Makecab.exe OR OriginalFileName = Mavinject.exe OR OriginalFileName = Microsoft.Workflow.r.exe OR OriginalFileName = Mmc.exe OR OriginalFileName = Msbuild.exe OR OriginalFileName = Msconfig.exe OR OriginalFileName = Msdt.exe OR OriginalFileName = Mshta.exe OR OriginalFileName = Msiexec.exe OR OriginalFileName = Odbcconf.exe OR OriginalFileName = Pcalua.exe OR OriginalFileName = Pcwrun.exe OR OriginalFileName = Presentationhost.exe OR OriginalFileName = Print.exe OR OriginalFileName = Reg.exe OR OriginalFileName = Regasm.exe OR OriginalFileName = Regedit.exe OR OriginalFileName = Register-cimprovider.exe OR OriginalFileName = Regsvcs.exe OR OriginalFileName = Regsvr32.exe OR OriginalFileName = Replace.exe OR OriginalFileName = Rpcping.exe OR OriginalFileName = Rundll32.exe OR OriginalFileName = Runonce.exe OR OriginalFileName = Runscripthelper.exe OR OriginalFileName = Sc.exe OR OriginalFileName = Schtasks.exe OR OriginalFileName = Scriptrunner.exe OR OriginalFileName = SyncAppvPublishingServer.exe OR OriginalFileName = Tttracer.exe OR OriginalFileName = Verclsid.exe OR OriginalFileName = Wab.exe OR OriginalFileName = Wmic.exe OR OriginalFileName = Wscript.exe OR OriginalFileName = Wsreset.exe OR OriginalFileName = Xwizard.exe OR OriginalFileName = Advpack.dll OR OriginalFileName = Comsvcs.dll OR OriginalFileName = Ieadvpack.dll OR OriginalFileName = Ieaframe.dll OR OriginalFileName = Mshtml.dll OR OriginalFileName = Pcwutl.dll OR OriginalFileName = Setupapi.dll OR OriginalFileName = Shdocvw.dll OR OriginalFileName = Shell32.dll OR OriginalFileName = Syssetup.dll OR OriginalFileName = Url.dll OR OriginalFileName = Zipfldr.dll OR OriginalFileName = Appvlp.exe OR OriginalFileName = Bginfo.exe OR OriginalFileName = Cdb.exe OR OriginalFileName = csi.exe OR OriginalFileName = Devtoolslauncher.exe OR OriginalFileName = dnx.exe OR OriginalFileName = Dxcap.exe OR OriginalFileName = Excel.exe OR OriginalFileName = Mftrace.exe OR OriginalFileName = Msdeploy.exe OR OriginalFileName = msxsl.exe OR OriginalFileName = Powerpnt.exe OR OriginalFileName = rcsi.exe OR OriginalFileName = Sqler.exe OR OriginalFileName = Sqlps.exe OR OriginalFileName = SQLToolsPS.exe OR OriginalFileName = Squirrel.exe OR OriginalFileName = te.exe OR OriginalFileName = Tracker.exe OR OriginalFileName = Update.exe OR OriginalFileName = vsjitdebugger.exe OR OriginalFileName = Winword.exe OR OriginalFileName = Wsl.exe OR OriginalFileName = CL_Mutexverifiers.ps1 OR OriginalFileName = CL_Invocation.ps1 OR OriginalFileName = Manage-bde.wsf OR OriginalFileName = Pubprn.vbs OR OriginalFileName = Slmgr.vbs OR OriginalFileName = Syncappvpublishingserver.vbs OR OriginalFileName = winrm.vbs OR OriginalFileName = Pester.bat)|eval CommandLine=lower(CommandLine)|eventstats count(process) as procCount by process|eventstats avg(procCount) as avg stdev(procCount) as stdev|eval lowerBound=(avg-stdev*1.5)|eval isOutlier=if((procCount < lowerBound),1,0)|where isOutlier=1|table host, Image, ParentImage, CommandLine, ParentCommandLine, procCount
