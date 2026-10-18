# Analizador de capturas de red

Guía sencilla para descargar, instalar y usar el analizador en tu ordenador. La aplicación lee archivos de captura `.pcap` y `.pcapng` y crea informes en texto y CSV. De forma opcional, puede consultar las IP públicas en VirusTotal.

> **Importante:** esta descarga contiene el programa en código fuente, no un instalador `.exe`. Para ejecutarlo en Windows necesitas Python y Wireshark/TShark. En Linux necesitas Python y TShark.

## Qué necesitas

- Un ordenador con Windows 10/11 o Linux.
- Una conexión a Internet para descargar el programa y preparar Python la primera vez.
- Python 3.10 o posterior.
- Wireshark con TShark, que es la herramienta que lee los archivos de captura.
- Un archivo de captura `.pcap` o `.pcapng`.
- Una clave de VirusTotal solo si quieres activar las consultas online. El análisis local funciona sin ella.

## Descargar la aplicación

En la página del proyecto de GitHub, pulsa **Code → Download ZIP** y extrae el ZIP en una carpeta fácil de encontrar, por ejemplo `C:\Analizador-red` en Windows o `~/Analizador-red` en Linux. No ejecutes el programa desde dentro del ZIP: primero hay que extraerlo.

## Instalación en Windows

### 1. Instala Python

Descarga Python desde [python.org](https://www.python.org/downloads/windows/). Durante la instalación, marca **Add python.exe to PATH**. Abre una ventana nueva de PowerShell y comprueba que está instalado:

```powershell
py --version
```

Debe aparecer Python 3.10 o una versión posterior.

### 2. Instala Wireshark y TShark

Descarga Wireshark desde [wireshark.org](https://www.wireshark.org/download.html) y asegúrate de instalar TShark. En PowerShell comprueba:

```powershell
tshark --version
```

Si el comando no se reconoce, cierra y vuelve a abrir PowerShell. Si sigue sin funcionar, el programa puede encontrar la instalación habitual automáticamente; si no, configura la ruta para esa sesión:

```powershell
$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

Si Wireshark está instalado en otra carpeta, sustituye la ruta por la ubicación real de `tshark.exe`.

### 3. Prepara el programa

Abre PowerShell en la carpeta extraída del proyecto. En el Explorador puedes abrir esa carpeta, hacer clic en la barra de direcciones, escribir `powershell` y pulsar Enter.

Ejecuta estos comandos desde la carpeta principal, donde está `pyproject.toml`:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

El primer comando crea un entorno privado de Python para esta aplicación. El segundo instala el programa en ese entorno. Esta preparación se hace una sola vez; la primera instalación necesita conexión a Internet.

### 4. Inicia la aplicación

En esa misma carpeta, ejecuta:

```powershell
.\.venv\Scripts\python.exe -m analizador
```

La próxima vez no es necesario reinstalar: abre PowerShell en la carpeta y ejecuta de nuevo ese comando.

## Instalación en Linux

Los siguientes comandos sirven para Kali, Debian y Ubuntu. Abre una terminal e instala Python y TShark:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip tshark
```

Ve a la carpeta donde extrajiste el proyecto. Por ejemplo:

```bash
cd ~/Analizador-red
```

Crea el entorno e instala la aplicación:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

> La instalación se hace una sola vez y necesita conexión a Internet. Para leer una captura guardada no hace falta habilitar la captura de paquetes sin privilegios.

Para iniciar el programa:

```bash
.venv/bin/python -m analizador
```

## Primer análisis

Al iniciar aparece un menú de texto:

1. Elige `1` para analizar una captura.
2. Escribe la ruta completa del archivo `.pcap` o `.pcapng`. En Windows puedes arrastrar el archivo desde el Explorador a la terminal para pegar su ruta.
3. Elige si quieres consultar VirusTotal. Para la primera prueba, responde `N`; así el análisis es local y no necesita clave ni Internet.
4. Escribe la carpeta donde quieres guardar los informes. Si pulsas Enter, se usará la carpeta `informes` dentro del proyecto. Si la carpeta indicada no existe, el programa la crea.
5. Espera a que aparezca el mensaje con la ubicación de los informes.

El programa crea dos archivos cuyo nombre empieza por el nombre de la captura:

- `Captura_informe.txt`: resumen fácil de leer con número de paquetes, protocolos, IPs, DNS y errores.
- `Captura_informe.csv`: datos organizados en columnas, que puedes abrir con Excel o LibreOffice Calc.

El analizador usa TShark para leer los paquetes de la captura. No inicia una captura de red en vivo ni sube el archivo PCAP.

## Crear una captura de prueba

Si todavía no tienes una captura, puedes crear una con Wireshark:

1. Abre Wireshark y elige una interfaz de red de tu propio ordenador.
2. Inicia la captura.
3. Genera algo de tráfico normal, por ejemplo, abre una página web.
4. Detén la captura y guárdala como `primera-prueba.pcapng`.
5. Usa ese archivo en el analizador.

Captura únicamente tráfico propio o para el que tengas autorización.

## Consultar VirusTotal (opcional)

### Obtener la clave

1. Crea una cuenta o inicia sesión en [VirusTotal Community](https://www.virustotal.com/gui/join-us).
2. Abre la página [Mi API key](https://www.virustotal.com/gui/my-apikey) y copia tu clave personal.
3. En la misma terminal desde la que inicias el programa, guarda la clave temporalmente.

En Windows PowerShell:

```powershell
$env:VT_API_KEY = "PEGA_AQUI_TU_CLAVE"
.\.venv\Scripts\python.exe -m analizador
```

En Linux:

```bash
export VT_API_KEY="PEGA_AQUI_TU_CLAVE"
.venv/bin/python -m analizador
```

Cuando el menú pregunte si quieres consultar las IP públicas en VirusTotal, responde `S`. No escribas la clave dentro del código ni la compartas en GitHub, capturas de pantalla o mensajes. La variable temporal desaparece al cerrar la terminal; tendrás que volver a configurarla en una sesión nueva.

### Qué ocurre durante la consulta

El programa envía a VirusTotal las IP públicas encontradas, una por una. La captura completa no se envía. La consola muestra el progreso, la IP que está consultando y si la consulta terminó bien o dio error. Se espera aproximadamente 15 segundos entre solicitudes para respetar el límite de la API pública; por eso, con muchas IPs el proceso puede tardar varios minutos.

VirusTotal advierte que los indicadores consultados pueden incorporarse a su conjunto de datos comunitario. No consultes IPs que revelen información sensible, confidencial o personal. Los límites y condiciones de la API pueden cambiar; consulta [su documentación](https://docs.virustotal.com/reference/public-vs-premium-api).

## Entender el informe

- **Paquetes analizados:** cantidad de paquetes de red leídos del archivo.
- **Protocolos:** protocolos detectados. Un mismo paquete puede aparecer en varias capas, por ejemplo Ethernet, IP, UDP y QUIC; por eso no se deben sumar esos números para calcular el total.
- **Direcciones IP:** IPs vistas en los paquetes y el número de referencias observadas.
- **Consultas DNS:** nombres de dominio observados en los mensajes DNS.
- **VirusTotal:** datos de reputación para las IPs consultadas, si se activó esa opción.
- **Errores:** consultas que no se pudieron completar. Un error en una IP no impide continuar con las siguientes.

Una etiqueta de VirusTotal no demuestra por sí sola que una conexión sea maliciosa. Las IPs pueden pertenecer a servicios compartidos, redes de distribución de contenido o servidores DNS.

## Si algo no funciona

- **No se encuentra Python:** instala Python desde [python.org](https://www.python.org/downloads/windows/) y abre una nueva terminal.
- **No se encuentra TShark:** instala Wireshark incluyendo TShark. En Windows puedes definir `TSHARK_PATH` como se explica arriba y luego iniciar el programa desde esa misma PowerShell.
- **No se encuentra el archivo de captura:** comprueba la ruta completa y que el archivo sea `.pcap` o `.pcapng`.
- **El menú no arranca:** asegúrate de ejecutar el comando desde la carpeta principal del proyecto y de haber completado la instalación.
- **La clave de VirusTotal no funciona o se agotó la cuota:** revisa que `VT_API_KEY` esté configurada en la terminal actual. También puedes elegir `N` y generar los informes sin VirusTotal.
- **La consulta tarda:** la consola muestra qué IP se está procesando. Las consultas se espacian para cumplir el límite por minuto.

## Privacidad y limitaciones

- El archivo PCAP se analiza localmente con TShark; no se sube a VirusTotal.
- Si activas VirusTotal, se envían las IP públicas consultadas y se necesita conexión a Internet.
- El programa resume lo que aparece en la captura; no descifra TLS/QUIC ni determina por sí solo quién generó una conexión o si hubo un incidente.
- Trata los informes como información potencialmente sensible: pueden incluir IPs y dominios observados en la red.
