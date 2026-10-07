# correo-escudo

[![CI](https://github.com/drewagaiin/correo-escudo/actions/workflows/ci.yml/badge.svg)](https://github.com/drewagaiin/correo-escudo/actions/workflows/ci.yml)

Hace poco, en una oficina de 15 personas, alguien recibe un correo "del gerente": que pague hoy a un proveedor nuevo, que no llame porque está en una reunión. El correo viene de un Gmail con el nombre del gerente, o de un dominio con una letra cambiada. Ese tipo de fraude no lleva virus, así que el antivirus no dice nada.

correo-escudo sirve para dos cosas:

1. **Revisar un correo raro** y decir, en español claro, si tiene pinta de fraude y por qué.
2. **Revisar el dominio de la empresa** para saber si cualquiera puede mandar correos haciéndose pasar por ella, y qué registros DNS hay que publicar para impedirlo.

Es un solo script de Bash para Linux (o Windows con WSL). Analizar un correo no usa internet y nunca abre sus enlaces ni sus adjuntos.

> ¿Eres el dueño o el encargado de una empresa y solo quieres saber qué hacer con un correo? Lee [QUE-HAGO.md](QUE-HAGO.md).

## Revisar un correo

```bash
./correo-escudo.sh analizar factura.eml --mi-dominio miempresa.com.pa
```

```text
  Veredicto: PELIGROSO
  No hagas clic en sus enlaces, no abras sus adjuntos y no respondas.

== Señales de peligro ==
  [CRÍTICO] BEC-CONFIRMED    Pide dinero o un cambio de cuenta Y el remitente no es quien dice ser: no pagues…
  [ALTO]    BEC-BANKCHANGE   Pide pagar a una cuenta bancaria nueva o distinta ("nueva cuenta bancaria, cambiamos…
  [MEDIO]   REPLYTO-DIFF     Las respuestas no van al remitente sino a pagos.carlos.perez@outlook[.]com
  [MEDIO]   FREEMAIL-ROLE    Se presenta como "Carlos Pérez - Gerente General" pero escribe desde un correo gratuito (gmail[.]com)
```

El veredicto es **PELIGROSO**, **SOSPECHOSO** o **SIN INDICIOS CLAROS**. Nunca dice "seguro": un correo bien hecho puede engañar a cualquier herramienta, así que si te piden dinero o la contraseña, se confirma por teléfono.

`--mi-dominio` no es obligatorio, pero ayuda mucho: con él detecta imitaciones como `rniempresa.com.pa` o `miempresa.com.pa.login-seguro.xyz`.

**Qué mira, en resumen** (la lista completa, con cada regla, está en [docs/DETECCIONES.md](docs/DETECCIONES.md)):

- Lo que comprobó **tu propio servidor** de correo (SPF, DKIM, DMARC), leyendo solo la cabecera de arriba, que es la única fiable.
- El **fraude del jefe o del proveedor**: Gmail con cargo de gerente, respuestas que van a otra dirección, cambio de cuenta bancaria, tarjetas de regalo, conversaciones secuestradas con un dominio casi igual.
- **Bancos y entidades de Panamá** usados como disfraz: Banco General, Yappy, Banistmo, BAC, Caja de Ahorros, Banconal y dominios `.gob.pa`, además de Microsoft, DHL, PayPal...
- **Enlaces** que dicen una cosa y llevan a otra, direcciones IP, acortadores, letras de otro alfabeto, permisos OAuth, formularios dentro del correo, enlaces dentro de PDF e invitaciones `.ics`.
- **Adjuntos**: `factura.pdf.exe`, nombres al revés (RTLO), `.iso`, `.svg` o `.html` con páginas falsas, macros, y `.zip` con contraseña o con un ejecutable dentro.
- Estafas **sin enlaces**: "llame a este número para cancelar el cobro" y "escanee este código QR".

Para sacar el `.eml`: en Gmail, abre el correo → ⋮ → *Descargar mensaje*. En Outlook web (outlook.office.com) → ⋯ → *Guardar como*. El Outlook de escritorio guarda `.msg`, que no sirve: abre el mismo correo en Outlook web.

## Revisar un dominio

```bash
./correo-escudo.sh dominio miempresa.com.pa
```

Te da una nota de la A a la F, lo que está bien, lo que falla y, al final, **cómo deberían quedar tus registros**, completos para copiar y pegar en el panel DNS. Reconoce si usas Microsoft 365 o Google Workspace y adapta las instrucciones, y te dice dónde está tu DNS (Cloudflare, GoDaddy, cPanel...).

Además de SPF, DKIM y DMARC (según el estándar nuevo, RFC 9989, de mayo de 2026), avisa de cosas que suelen pasar desapercibidas: un SPF que autoriza medio internet, un servidor de correo que ya no existe (y cuyo dominio alguien podría registrar), informes DMARC que se pierden, o un dominio sin usar que cualquiera puede usar para suplantarte.

Si tienes varios clientes: `./correo-escudo.sh lista clientes.txt` (un dominio por línea) saca una tabla con todos.

## Instalar

```bash
sudo apt install dnsutils          # dig; en Kali ya viene
git clone https://github.com/drewagaiin/correo-escudo.git
cd correo-escudo && chmod +x correo-escudo.sh
```

En Windows: abre PowerShell como administrador, ejecuta `wsl --install`, reinicia, abre "Ubuntu" y sigue los pasos de arriba. Tus descargas de Windows están en `/mnt/c/Users/TU_USUARIO/Downloads/`.

## Para equipos de seguridad

- `--format json` da un JSON con `schema_version`, veredicto en inglés (`verdict_code`), fecha ISO, Message-ID, IP de origen, URLs completas, SHA-256 de cada adjunto y la técnica MITRE ATT&CK de cada señal.
- Acepta varios archivos, una carpeta o la entrada estándar (`-`). Con varios correos y `--format json` saca **JSON Lines**, una línea por correo, lista para un SIEM.
- `--anonimizar` quita nombres, asuntos y la parte local de las direcciones, por si el informe va a salir de tu equipo.
- Códigos de salida: `0` sin indicios · `1` sospechoso · `3` peligroso · `2` error. En `dominio`: `1` si hay problemas altos o críticos, `2` si no se pudo comprobar todo.
- Velocidad orientativa: unos 100 ms por correo normal; 25 correos de prueba en 1 segundo.

## Lo que no hace

No bloquea nada ni toca tu servidor de correo. No consulta listas de reputación ni la antigüedad de los dominios (eso necesita internet y servicios de pago). De los PDF solo saca los enlaces que llevan dentro, sin abrirlos ni ejecutarlos. Las imágenes no las mira: si el enlace está dentro de un código QR, avisa del truco pero no puede leer el enlace.

## Cómo se ha probado

67 pruebas automáticas sin red, con correos de ejemplo y respuestas DNS simuladas, que pasan igual con las dos versiones de awk que traen Kali, Debian y Ubuntu (mawk y gawk). Antes de publicarlo pedí a varios revisores (agentes de IA independientes, cada uno con un enfoque distinto: seguridad del propio programa, detección de amenazas actuales y uso en empresas) que intentaran romperlo. Cada fallo que encontraron está corregido y convertido en prueba; el [CHANGELOG](CHANGELOG.md) los cuenta uno por uno.

## Privacidad

Los correos y los informes contienen datos personales. Analiza solo correos tuyos o con permiso, guarda los informes mientras dure la investigación y luego bórralos. Los informes que guarda el programa (`-o`) quedan con permisos 600 (solo tu usuario puede leerlos). No subas correos reales a GitHub: el `.gitignore` ya excluye la carpeta `correos-reales/`.

## Parte de un kit

[linux-audit](https://github.com/drewagaiin/linux-audit) revisa la configuración de los servidores, [ssh-sentinel](https://github.com/drewagaiin/ssh-sentinel) vigila los accesos SSH y correo-escudo se ocupa del correo, que es por donde entran la mayoría de los problemas.

Licencia [MIT](LICENSE). Hecho por Andrés Clark en Panamá.
