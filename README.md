# Analizador de capturas de red

Herramienta de consola para analizar archivos PCAP/PCAPNG con TShark, resumir protocolos, direcciones IP, conversaciones y DNS, y guardar informes TXT y CSV. Opcionalmente consulta la reputación de las IP públicas en VirusTotal API v3. Si una consulta falla, registra el error y continúa con las siguientes IP.

> El documento de la práctica y el borrador mencionados en la conversación de origen no están disponibles en el espacio de trabajo recibido. Este proyecto implementa el diseño confirmado en esa conversación; contrasta el alcance con la práctica antes de entregarlo como evidencia académica.

## Funciones

- Análisis local de PCAP y PCAPNG con TShark.
- Resumen de paquetes y protocolos, IPs, conversaciones TCP/UDP y nombres/respuestas DNS.
- Exclusión automática de IP privadas, loopback, reservadas y no globales al consultar VirusTotal.
- Informes TXT y CSV con resultados parciales y errores de VirusTotal.
- Sin caché de consultas ni envío de la captura completa.
- Clave leída de la variable de entorno `VT_API_KEY`, nunca guardada en el repositorio.

## Requisitos

- Python 3.10 o posterior.
- Wireshark/TShark instalado y disponible como `tshark` en el `PATH`.
- Clave de VirusTotal Community, solo si se activa la consulta online.

### Instalar TShark

**Kali/Debian/Ubuntu**

```bash
sudo apt update
sudo apt install tshark
tshark --version
```

En el diálogo de instalación, permite capturar paquetes como usuario no privilegiado solo si necesitas capturar tráfico en vivo. Este programa únicamente lee archivos ya guardados y no necesita permisos de captura.

**Windows**

Instala Wireshark desde [wireshark.org](https://www.wireshark.org/download.html) y asegúrate de incluir TShark. Normalmente se encuentra en `C:\Program Files\Wireshark`; añade esa carpeta al `PATH` o configura la variable `TSHARK_PATH` (consulta la sección de configuración). Abre una terminal nueva y comprueba `tshark --version`.

**macOS**

Instala Wireshark desde [wireshark.org](https://www.wireshark.org/download.html) o, si usas Homebrew, `brew install --cask wireshark`. Comprueba que `tshark --version` funciona desde la terminal.

## Instalación del proyecto

```bash
git clone https://github.com/USUARIO/analizador-capturas-red.git
cd analizador-capturas-red
python -m venv .venv
```

Activa el entorno virtual:

```bash
# Linux/macOS/Kali
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Windows CMD
.venv\Scripts\activate.bat
```

Instala dependencias y el programa:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Si la activación de PowerShell está bloqueada por una directiva del equipo, utiliza CMD o Git Bash; no es necesario cambiar la política global de Windows.

## Obtener y configurar la API key de VirusTotal

1. Crea una cuenta o inicia sesión en [VirusTotal Community](https://www.virustotal.com/gui/join-us).
2. Abre el perfil de usuario y copia la API key personal desde la sección de API key.
3. Configúrala solo en la sesión de terminal que ejecutará el programa:

```bash
# Linux/macOS/Kali (temporal, hasta cerrar esta terminal)
export VT_API_KEY="TU_CLAVE"

# Windows PowerShell (temporal, hasta cerrar esta terminal)
$env:VT_API_KEY = "TU_CLAVE"

# Windows CMD (temporal)
set VT_API_KEY=TU_CLAVE
```

No pegues la clave en el código, README, capturas de pantalla, informes, issues públicos ni repositorio. No uses un archivo `.env` sin excluirlo de Git. Si una clave se publica accidentalmente, revócala y genera otra desde VirusTotal.

La consulta es opcional: se puede analizar y exportar una captura sin clave ni conexión a VirusTotal.

## Uso

Inicia el menú:

```bash
analizador-capturas
# También funciona:
python -m analizador
```

Selecciona la opción de análisis, introduce la ruta del archivo y decide si deseas consultar las IP públicas en VirusTotal. Los archivos resultantes se guardan en `informes/` junto a la carpeta de trabajo, con sufijos `_informe.txt` y `_informe.csv`.

Ejemplo de ruta en Kali:

```text
/home/kali/capturas/ejemplo.pcapng
```

Ruta con espacios: introdúcela completa; el programa elimina comillas exteriores. También puede usarse la librería desde Python:

```python
from analizador.cli import process_capture

report, vt_results, errors = process_capture(
    "captura.pcapng", output_dir="informes", vt_enabled=False
)
print(report["packets"], len(report["ips"]), errors)
```

## Privacidad, límites y alcance de VirusTotal

- Se envían únicamente las direcciones IP globales consultadas, mediante HTTPS y la cabecera `x-apikey`; el PCAP no se sube.
- VirusTotal advierte que los indicadores consultados mediante API se escanean y se añaden a su conjunto de datos, donde pueden quedar accesibles a la comunidad. No consultes IPs que revelen información confidencial, personal o sensible.
- La API pública está limitada actualmente a 4 solicitudes por minuto y 500 al día, y no se permite su uso en productos o servicios comerciales. El cliente espera entre consultas para respetar el límite por minuto; la cuota diaria depende de la cuenta. Comprueba las condiciones vigentes de tu cuenta antes de uso intensivo.
- Una IP sin informe, una clave inválida, una cuota agotada u otro error queda anotado en el TXT/CSV y no detiene las consultas siguientes.
- Una dirección marcada como maliciosa/sospechosa por motores de terceros no constituye por sí sola una atribución ni una conclusión definitiva. Interpreta resultados con contexto.
- Las IP obtenidas de una captura son indicadores observados, no necesariamente los sistemas de origen del incidente: pueden ser CDN, DNS públicos, NAT o infraestructura compartida.

## Pruebas

Las pruebas usan respuestas simuladas y un TShark falso; no requieren clave, conexión de red ni instalación real de Wireshark:

```bash
python -m unittest discover -s tests -v
```

Las pruebas comprueban extracción y filtrado, respuestas de VirusTotal, continuidad ante fallos y generación de informes. Para analizar capturas reales, TShark sí debe estar instalado.

## Subir a GitHub

1. Crea un repositorio vacío en GitHub, sin marcar la opción para añadir README si ya vas a subir este proyecto.
2. Revisa que no haya capturas sensibles, claves ni resultados privados en el directorio.
3. Desde la carpeta raíz del proyecto:

```bash
git init
git add .
git status
git commit -m "Añade analizador de capturas de red"
git branch -M main
git remote add origin https://github.com/USUARIO/analizador-capturas-red.git
git push -u origin main
```

Sustituye `USUARIO` por tu cuenta u organización. GitHub puede pedir autenticación mediante navegador o token personal; no escribas credenciales en el código ni las compartas. Si el repositorio ya existe localmente, revisa `git status` y la URL remota antes de hacer `push`.

## Limitaciones

- La precisión de campos y protocolos depende de la versión de TShark y de lo que pueda decodificarse de la captura.
- No reconstruye archivos/contenidos, no descifra TLS, no determina causalidad y no sustituye un análisis forense completo.
- Los informes pueden contener IPs, dominios y metadatos operativos; trátalos según la sensibilidad de la captura.
- En este entorno de generación no estaba accesible el documento Word original; algunos requisitos particulares de la práctica podrían no estar representados.

## Documentación oficial

- [Instalación de Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)
- [VirusTotal: autenticación](https://docs.virustotal.com/reference/authentication)
- [VirusTotal: informe de dirección IP](https://docs.virustotal.com/reference/ip-info)
- [VirusTotal: API pública y límites](https://docs.virustotal.com/reference/public-vs-premium-api)
- [VirusTotal: descripción de la API](https://docs.virustotal.com/docs/api-overview)
