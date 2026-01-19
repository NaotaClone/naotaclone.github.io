---
title: "Go Go Power Rangers (Anubis Ransomware - Caso COPEC)"
date: 2026-01-16
tags: [ransomware, threat intelligence, purple team, blue team, threat hunting]
---
> _Only with educational proposals | Este contenido tiene unicamente fines educativos_

# Caso COPEC

El 9 de enero, el actor de amenazas **Anubis** publicó en su sitio de filtraciones (**DLS - Data Leak Site**) información relativa a una brecha de datos de **6 TB** que afecta a la empresa chilena **COPEC**. Este incidente representa la primera filtración masiva de datos en el país durante el año 2026 bajo la vigencia de la [**Ley 21.663**](https://www.bcn.cl/leychile/navegar?idNorma=1202434) y tras la publicación del listado oficial de [**Operadores de Importancia Vital (OIV)**](https://www.diariooficial.interior.gob.cl/publicaciones/2025/12/17/44326-B/01/2743431.pdf), listado al que se señala COPEC en la categoría de energia.

![Imagen DLS - Sitio](/assets/images/anubis/site-public.png)

Como prueba del compromiso, los atacantes difundieron imágenes de **cámaras de vigilancia de estaciones de servicio**, además de una captura de pantalla que documenta la negociación entre representantes de la compañía y el grupo criminal. En los registros se observa un intento de negociación con una oferta inicial de **400.000 USD**, decisión que posteriormente fue rectificada por la empresa, optando por no realizar ningún pago por el rescate de la información.

![Imagen DLS - Negociación](/assets/images/anubis/dls.png)

Con el propósito de identificar el alcance del material comprometido, se procedió a la descarga del árbol de directorios expuesto por el atacante. Cabe destacar que este análisis se limitó exclusivamente a la visualización de la estructura y nombres de archivos, **sin realizar en ningún momento la descarga del contenido original ni la revisión de los datos sensibles**. En dicho listado se identificaron artefactos que sugieren la filtración de la base de usuarios de la organización.

![Imagen DLS - Usuarios](/assets/images/anubis/findstr-usuarios.png)

# Anubis como Actor de Amenaza

![Imagen - Anubis Avatar](/assets/images/anubis/anubis.png)

Anubis inició sus operaciones durante el **Q4** de **2024**, promocionando un nuevo programa de afiliados para su servicio **RaaS (Ransomware as a Service)** en diversos foros especializados. Bajo el seudónimo **superSonic**, el actor de amenaza destacó características avanzadas en su carga útil, tales como:

* Algoritmo de cifrado de alta velocidad basado en **ChaCha + ECIES**.
* Soporte multiplataforma para entornos **Windows, Linux, NAS y ESXi** en arquitecturas **x64/x32**.
* Capacidad de realizar **consultas LDAP** para el descubrimiento de recursos compartidos en la red.
* Mecanismos de elevación de privilegios hasta el nivel de **NT AUTHORITY\SYSTEM**.
* Terminación automatizada de servicios críticos para el proceso de cifrado y apagado forzado de instancias virtuales (**VM**).

![Imagen DLS - superSonic](/assets/images/anubis/supersonic.png)

El operador afirma contar con la capacidad de generar reportes de compromiso en tiempo real sobre sus víctimas. Respecto a su política de exclusión, señalan que no dirigen ataques contra países de la **ex URSS** o miembros del **BRICS**, ni sobre **redes cifradas hace menos de un año**. Su modelo de monetización se basa en una distribución de ganancias del **50/50**, mientras que diversas fuentes de inteligencia confirman que el grupo emplea tácticas de **doble extorsión**.

![Imagen DLS - modus](/assets/images/anubis/modus.png)

> Es importante precisar que **Anubis Ransomware** no guarda relación con el **malware Anubis** orientado a dispositivos móviles (enfocado en robo de credenciales, interceptación de audio, captura de pantalla, keylogger, etc.).

`**Sitio DLS**: https://om6q4a6cyipxvt7ioudxt24cw4oqu4yodmqzl25mqd2hgllymrgu4aqd.onion`

## Análisis de "anubis.exe"

Con el objetivo de identificar las **TTPs (Tácticas, Técnicas y Procedimientos)** empleadas por este actor ante la escasez de **Indicadores de Compromiso (IoC)** públicos, se tomó como referencia el indicador reportado por el [equipo de investigación de TrendMicro](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/25/f/anubis--a-closer-look-at-an-emerging-ransomware-with-built-in-wiper/Anubis_A_Closer_Look_at_a_Emerging_Ransomware_with_Built-in_Wiper_IOCs.txt) el 13 de junio de 2025.

```
SHA256							Detection name
98a76aacbaa0401bac7738ff966d8e1b0fe2d8599a266b111fdc932ce385c8ed	Ransom.Win64.NUBIAS.THDBIBE.go
```
Cabe destacar que la variante a analizar esta escrita en **Go** y utiliza bibliotecas de diversos repositorios de **Github** que serán detallados más adelante.

### Análisis Estático

Dentro de la función **main_main**, se identifica el uso de una llave de ejecución obligatoria: **TLGHTUAFBRFsWLJNCBAICPeOsrpJlAwSGuyF**. Esta debe ser proporcionada mediante el argumento **/KEY=**, resultando en la línea de comandos: **anubis.exe /KEY=TLGHTUAFBRFsWLJNCBAICPeOsrpJlAwSGuyF**.

![Imagen DLS - main](/assets/images/anubis/main.png)

Durante la ejecución en un entorno controlado, se validó que el binario realiza una comprobación de privilegios inicial. Aunque el malware permite continuar la ejecución incluso si no detecta permisos elevados, procede a cifrar todos los archivos accesibles, añadiendo la extensión **.anubis**.

![Imagen DLS - ejecucion1](/assets/images/anubis/ejecucion1.png)

Como se observa en la evidencia anterior, este ransomware permite la interrupción manual del proceso mediante la combinación **CTRL + C**. Al ejecutar este comando, el binario finaliza su actividad y despliega un resumen detallado de las operaciones de cifrado realizadas.

![Imagen DLS - Cifrado-Resultado](/assets/images/anubis/ejecucion2.png)

Adicionalmente, en la función **main_main** se identificaron otros parámetros críticos, como **/WIPEMODE**, diseñado para dejar las unidades de almacenamiento irrecuperables, y **/elevated**, orientado a la escalada de privilegios en el sistema.

![Imagen DLS - main2](/assets/images/anubis/main2.png)

Al activar la opción **/WIPEMODE**, el binario solicita una contraseña que es contrastada con la cadena **OpBNmjcVBtMQmrofQpiJPfFZhudogNITGico**. Si la validación es exitosa, el proceso de destrucción continúa; de lo contrario, se invoca la función **os_Exit** para terminar la ejecución de forma inmediata.

![Imagen DLS - wipemode](/assets/images/anubis/wipemode.png)
![Imagen DLS - comparacion](/assets/images/anubis/comparacion.png)

El malware también permite especificar directorios concretos para aplicar el borrado físico (**WIPE**). Antes de proceder, el binario implementa un control de seguridad que requiere una confirmación explícita del usuario, mitigando ejecuciones accidentales en modo *wiper*.

![Imagen DLS - wipeconfirm](/assets/images/anubis/wipeconfirm.png)

> El binario incluye rutinas de validación para verificar la existencia previa de los directorios antes de iniciar cualquier operación.

Respecto a la comprobación de privilegios de administrador, el ejecutable intenta acceder a [**\\\\.\\PHYSICALDRIVE0**](https://attack.mitre.org/detectionstrategies/DET0137/). En el flujo lógico, si el registro **RBX** es **0**, se asigna un **1** a **AL** confirmando el acceso exitoso a la unidad física. Cualquier otro valor de retorno indica falta de permisos, determinando que el proceso no cuenta con privilegios elevados.

![Imagen DLS - com-priv](/assets/images/anubis/com-priv.png)

Por otro lado, la elevación de privilegios al momento de utilizar la opción **/elevated** es generada a través de la habilitación de **SeDebugPrivilege** dado que permite la inyección de codigo, acceder a la memoria y crear handles a procesos que pudiesen estar protegidos. Esto puede ser en base al acceso a procesos como **winlogo.exe** o **lsass.exe**.

![Imagen DLS - Elev Priv](/assets/images/anubis/privElev.png)

Adicionalmente, dentro de las numerosas bibliotecas exportadas desde GitHub señaladas en el punto anterior, el binario incorpora llamadas a **Syscalls** empleadas por **Sliver C2**. Entre las funciones identificadas destacan:

* **GetProcessHeap**: Obtiene el *heap* del proceso actual para gestionar asignaciones internas.  
* **HeapAlloc**: Reserva memoria dinámica en el *heap* del proceso, utilizada comúnmente para preparar estructuras o buffers antes de una inyección.  
* **HeapFree**: Libera memoria previamente asignada, evitando dejar artefactos innecesarios en memoria.  
* **InitializeProcThreadAttributeList**: Prepara estructuras avanzadas de atributos para creación de procesos bajo condiciones controladas *(Ej PPID spoofing o process hollowing)*.  
* **UpdateProcThreadAttribute**: Actualiza los atributos de la estructura anterior, permitiendo redireccionar handles, mapear memoria o configurar herencia de procesos modificada.

![Imagen DLS - discovery](/assets/images/anubis/sliver.png)

Se puede observar por ejemplo que a través de **UpdateProcThreadAttribute** y luego la función **CreateProcessAsUser** dan como resultado el escalamiento como  **NT AUTHORITY\\\\SYSTEM**.

![Imagen DLS - discovery](/assets/images/anubis/ntuser.png)

Finalmente, se identificó una lista de tareas administrativas ejecutadas por el Ransomware:

* **stopSystemServices**: Detención de servicios del sistema que puedan bloquear o interferir con el cifrado.
* **terminateProcesses**: Finalización de procesos activos que mantengan archivos en uso.
* **removeShadowCopies**: Eliminación de *Volume Shadow Copies* para impedir la recuperación de datos.
* **extractEmbeddedAssets**: Extracción de recursos embebidos en el binario *(como **icon.ico** y **wall.jpg**)*.

![Imagen DLS - admintask](/assets/images/anubis/admintask.png)


Cuando se inicia la ejecución de **anubis.exe**, mediante la importación de **StackExchange_WMI()** corre la consulta SQL **"SELECT * FROM Win32_Service WHERE Name = '%s'"** para identificar si existen los servicios contenidos en la variable **%s**.

![Imagen DLS - WMI Servicios](/assets/images/anubis/wmi-servicios2.png)

Dentro de la variable **%s** el artefacto busca los siguientes servicios:
```
SQLPBDMS, SQLPBENGINE, MSSQLFDLauncher, SQLSERVERAGENT, MSSQLServerOLAPService, SSASTELEMETRY, SQLBrowser, SQL Server Distributed Replay Client, SQL Server Distributed Replay Controller, MsDtsServer150, SSISTELEMETRY150, SSISScaleOutMaster150, SSISScaleOutWorker150, MSSQLLaunchpad, SQLWriter, SQLTELEMETRY, MSSQLSERVER, AcronisAgent, AcrSch2Svc, backup, BackupExecAgentAccelerator, BackupExecAgentBrowser, BackupExecDiveciMediaService, BackupExecJobEngine, BackupExecManagementService, BackupExecRPCService, BackupExecVSSProvider, CAARCUpdateSvc, CASAD2DWebSvc, ccEvtMgr, ccSetMgr, DefWatch, GxBlr, GxCIMgr, GxCVD, GxFWD, GxVss, Intuit.QuickBooks.FCS, memtas, mepocs, PDVFSService, QBCFMonitorService, QBFCService, QBIDPService, RTVscan, SavRoam, sophos, sql, stc_raw_agent, svc$, veeam, VeeamDeploymentService, VeeamNFSSvc, VeeamTransportSvc, VSNAPVSS, vss, YooBackup, YooIT
```

Una vez identificados los servicios, este ejecuta **sc stop <Nombre_Servicio>** para detener cualquier servicio que pueda interrumpir el cifrado.

![Imagen DLS - WMI Servicios](/assets/images/anubis/wmi-servicios.png)

Por otra parte, el artefacto incluye rutinas diseñadas para identificar todas las unidades de almacenamiento presentes en el equipo (función **AvailableDrives**). Para ello, realiza un barrido sistemático del abecedario mediante la instrucción: **("ABCDEFGHIJKLMNOPQRSTUVWXYZ" + ":\\\\")**.

![Imagen DLS - unidades](/assets/images/anubis/unidades.png)

Tras el reconocimiento de las unidades, el malware procede a comprometer cada volumen identificado mediante la ejecución de la función **main_encryptAllDrives()**.

![Imagen DLS - unidades2](/assets/images/anubis/unidades2.png)


Una vez finalizado el cifrado de los discos y eliminado los servicios señalados junto los procesos en ejecución, el ransomware intenta inhabilitar los mecanismos de recuperación del sistema para impedir la restauración de datos. Esto se lleva a cabo mediante la ejecución del comando: **vssadmin delete shadows /for=norealvolume /all /quiet**, orientado a la eliminación silenciosa de las copias de seguridad de volumen *(Shadow Copies)*.

![Imagen DLS - shadowcopy](/assets/images/anubis/shadowcopy.png)

Como se ha mencionado, el ransomware ejecuta tareas adicionales para modificar la estética del endpoint comprometido. Para ello, extrae dos artefactos en el directorio **C:\\\\ProgramData\\**: el archivo **icon.ico**, utilizado para sustituir los iconos del sistema por el logotipo de **Anubis**, y **wall.jpg**, que corresponde al fondo de pantalla con la nota de rescate.

![Imagen DLS - fondito](/assets/images/anubis/fondito.png)

La modificación del fondo de pantalla se realiza mediante la ejecución del comando: **reg add "%s" /v Wallpaper /t REG_SZ /d "%s" /f**. En este caso, el malware reemplaza las variables para apuntar al recurso alojado en **C:\\\\ProgramData\wall.jpg**, resultando en la instrucción final: **reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /t REG_SZ /d "C:\\\\programdata\wall.jpg" /f**.

![Imagen DLS - fondito2](/assets/images/anubis/fondito2.png)

Además, busca modificar los iconos de todos los archivos que contengan la extensión **.anubis**.

![Imagen DLS - fondito2](/assets/images/anubis/icon-anubis.png)

En paralelo el **Ransomware** genera multiples tareas como:

* El reconcomiento de recursos compartidos de red a través de **SMB**.
    ![Imagen DLS - smb](/assets/images/anubis/recursos-compartidos.png)
* La identificación de los **Controladores de Dominio (DC)** existentes en la red a traves de **Consultas LDAP** a los puertos **389** & **636**.
    ![Imagen DLS - ldap](/assets/images/anubis/ldap.png)
* Identificación de los endpoints dentro del dominio mediante el **filtro de búsqueda LDAP -> (objectCategory=computer)** donde extrae los valores **sAMAccountName** & **dNSHostName**.
    ![Imagen DLS - discovery](/assets/images/anubis/discovery.png)

> **Cabe destacar que el actor genera la nota de rescate en un formato html**.
> ![Imagen DLS - discovery](/assets/images/anubis/notarescate.png)


### Bibliotecas de Terceros (GitHub)

A continuación, se detallan las bibliotecas de repositorios externos integradas en el binario **anubis.exe**, clasificadas por **Categoría** y **Descripción Técnica** cuales a su vez, si no forman parte de los desarrollos internos de la organización a la que pertenezcas, puede ser tomados como **Indicadores de Compromiso**:

| **Biblioteca**                                        | **Categoría**           | **Descripción**                                                           |
| ----------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------- |
| `github.com/StackExchange/wmi`                        | Windows - WMI           | Acceso a WMI(Enum. procesos, servicios, hardware y usuarios en Windows). |
| `github.com/yusufpapurcu/wmi`                         | Windows - WMI           | Wrapper alternativo de WMI en Go.      |
| `github.com/go-ole/go-ole`                            | Windows - COM           | Interacción con COM/OLE; base para WMI.                |
| `github.com/go-ole/go-ole/oleutil`                    | Windows - COM           | Utilidades de alto nivel para llamadas COM/OLE.                                 |
| `github.com/cloudfoundry/gosigar/sys/windows`         | Sistema - Recon         | Obtención de información del sistema (CPU, memoria, uso).                          |
| `github.com/alexbrainman/sspi`                        | Autenticación           | Implementación SSPI para autenticación nativa de Windows.                       |
| `github.com/alexbrainman/sspi/kerberos`               | Kerberos                | Uso de Kerberos vía SSPI sin manejar credenciales explícitas.                   |
| `github.com/go-ldap/ldap/v3`                          | AD - LDAP | Cliente LDAP completo para enumeración y consultas en AD.                       |
| `github.com/go-ldap/ldap/v3/gssapi`                   | AD - Kerberos           | LDAP autenticado mediante Kerberos (GSSAPI).                                    |
| `github.com/jcmturner/gokrb5/v8/iana/errorcode`       | Kerberos                | Definiciones de códigos de error Kerberos.                                      |
| `github.com/jcmturner/gokrb5/v8/iana/etypeID`         | Kerberos                | Identificadores de tipos de cifrado Kerberos.                                   |
| `github.com/jcmturner/gokrb5/v8`                      | Kerberos                | Implementación completa del protocolo Kerberos en Go.                           |
| `github.com/jcmturner/gofork/encoding/asn1`           | Protocolos              | Codificación ASN.1 requerida por Kerberos y LDAP.                               |
| `github.com/go-asn1-ber/asn1-ber`                     | Protocolos              | Codificación ASN.1/BER para LDAP y protocolos legacy.                           |
| `github.com/ecies/go`                                 | Crypto            | Cifrado ECIES.                                       |
| `github.com/fomichev/secp256k1`                       | Crypto            | Implementación de secp256k1.                                  |
| `github.com/chocolatkey/chacha8`                      | Crypto            | Implementación ligera de ChaCha.                                      |
| `github.com/chocolatkey/chacha8/internal/hardware`    | Crypto            | Optimizaciones ChaCha usando capacidades del hardware.                          |
| `github.com/chocolatkey/chacha8/internal/ref`         | Crypto          | Implementación de referencia (fallback).                                 |
| `github.com/mitchellh/go-ps`                          | Recon local             | Enumeración de procesos del sistema.                                            |
| `github.com/shirou/gopsutil/cpu`                      | Sistema - Recon         | Información detallada de CPU.                                                   |
| `github.com/shirou/gopsutil/mem`                      | Sistema - Recon         | Estadísticas de memoria del sistema.                                            |
| `github.com/shirou/gopsutil/net`                      | Sistema - Red           | Información de interfaces y conexiones de red.                                  |
| `github.com/shirou/gopsutil/process`                  | Sistema - Recon         | Detalles de procesos activos.                                                   |
| `github.com/shirou/gopsutil/internal/common`          | Sistema                 | Utilidades internas compartidas de gopsutil.                                    |
| `github.com/karrick/godirwalk`                        | Filesystem              | Recorrido rápido de directorios y archivos.                                     |
| `github.com/google/uuid`                              | Utils                | Generación de identificadores únicos (UUID).                                    |
| `github.com/pkg/errors`                               | Utils                | Manejo avanzado de errores con stack trace.                                     |
| `github.com/bishopfox/sliver/implant/sliver/syscalls` | Evasion - C2            | Uso de syscalls directos del implante Sliver para evadir EDR.                   |

> **Nota:** El uso de bibliotecas de código abierto ampliamente documentadas permite al actor de amenaza reducir los tiempos de desarrollo y minimizar la firma heurística del malware al reutilizar código legítimo.

# Tácticas, Técnicas & Procedimientos Identificados

* **T1059 - Command and Scripting Interpreter**: Ejecución controlada mediante argumentos obligatorios (**/KEY=**, **/WIPEMODE**, **/elevated**) que gobiernan el flujo del binario desde la línea de comandos.
* **T1106 - Native API**: Uso directo de APIs nativas y syscalls (por ejemplo **HeapAlloc**, **UpdateProcThreadAttribute**) para gestionar memoria, crear procesos y evadir mecanismos de monitoreo de alto nivel.
* **T1486 - Data Encrypted for Impact**: Cifrado masivo de archivos accesibles en todas las unidades detectadas, agregando la extensión **.anubis**.
* **T1490 - Inhibit System Recovery**: Eliminación explícita de Volume Shadow Copies mediante **vssadmin delete shadows**, impidiendo la recuperación del sistema.
* **T1489 - Service Stop**: Detención sistemática de servicios críticos (SQL, soluciones de backup, Veeam, Acronis y antivirus) mediante **sc stop** para maximizar el impacto del cifrado.
* **T1047 - Windows Management Instrumentation**: Uso de consultas **WMI (Win32_Service)** para identificar servicios activos antes de proceder a su detención.
* **T1083 - File and Directory Discovery**: Enumeración de todas las unidades locales mediante un barrido del abecedario (**A:\\\\** a **Z:\\\\**) previo al cifrado.
* **T1135 - Network Share Discovery**: Reconocimiento de recursos compartidos a través de SMB, permitiendo identificar volúmenes de red potencialmente afectados.
* **T1482 - Domain Trust Discovery**: Identificación de Controladores de Dominio mediante consultas LDAP a los puertos **389** y **636**.
* **T1018 - Remote System Discovery**: Enumeración de equipos dentro del dominio mediante consultas LDAP **(objectCategory=computer)**, extrayendo atributos como **sAMAccountName** y **dNSHostName**.
* **T1548.002 - Abuse Elevation Control Mechanism**: Escalada de privilegios mediante la habilitación de **SeDebugPrivilege** y la creación de procesos con contexto elevado (**NT AUTHORITY\SYSTEM**).
* **T1561.002 - Disk Wipe**: Modo **/WIPEMODE** diseñado para la destrucción irrecuperable de datos y volúmenes, funcionando como un wiper integrado al ransomware.
* **T1112 - Modify Registry**: Modificación del registro de Windows para alterar el fondo de pantalla y mostrar la nota de rescate.

## Indicadores de Ataque (IoA)

**Ejecución de binario con parámetro obligatorio /KEY=**  
  ```regex
  (?gm)\.exe.*\/KEY=
  ```

**Ejecución con modo wiper (/WIPEMODE)**  
  ```regex
  (?gm)\.exe.*\/KEY=.*\/WIPEMODE
  ```

**Ejecución con elevación explícita (/elevated)**  
  ```regex
  (?gm)\.exe.*\/KEY=.*\/elevated
  ```

**Detención de servicios**  
  ```regex
  (?gm)\bsc\s+stop\s+\S+
  ```

**Eliminación de Shadow Copies**  
  ```regex
  (?gm)\bvssadmin.*delete\s+shadows
  ```

**Modificación del fondo de pantalla vía registro**  
  ```regex
  (?gm)\breg\s+add.*Wallpaper
  ```

**Apertura de nota de rescate en formato HTML**  
  ```regex
  (?gm)(chrome|msedge|firefox|iexplore)\.exe.*\.html
  ```

**Creación/uso de artefactos en ProgramData**  
```regex
  (?gm)ProgramData\\.*\.(jpg|ico|html)
  ```

## Regla Yara - Detección Anubis

```
import "pe"

rule Anubis_Ransomware_Himitsu
{
  meta:
    author = "Himitsu"
    description = "Regla basado en el analisis de la muestra de Anubis Ransomware"

  strings:

    $wall = "wall.jpg" ascii wide
    $icon = "icon.ico" ascii wide

    $go1 = "Go build ID:" ascii
    $go2 = "runtime." ascii
    $go3 = ".gopclntab" ascii

    $gh1 = "github.com/shirou" ascii wide
    $gh2 = "github.com/bishopfox" ascii wide
    $gh3 = "github.com/mitchellh/go-ps" ascii wide
    $gh4 = "github.com/yusufpapurcu/wmi" ascii wide

    $slv1 = "bishopfox/sliver/implant/sliver/syscalls" ascii wide
    $slv2 = "github.com_bishopfox_sliver_implant_sliver_syscalls" ascii wide
    $slv3 = "syscalls.GetProcessHeap" ascii wide
    $slv4 = "GetProcessHeap" ascii wide

  condition:
    pe.is_pe
    and all of ($wall, $icon)
    and 1 of ($go1, $go2, $go3)
    and 1 of ($gh1, $gh2, $gh3, $gh4)
    and 1 of ($slv1, $slv2, $slv3, $slv4)
}
```

