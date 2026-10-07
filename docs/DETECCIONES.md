# Qué detecta y cómo decide

Cada señal tiene un código (por ejemplo `BEC-BANKCHANGE`) que no cambia entre versiones, para que puedas filtrar por él en un SIEM.

## El veredicto de un correo

Cada señal suma puntos: crítica 50, alta 25, media 10, baja 3.

- **PELIGROSO**: alguna señal crítica o 50 puntos o más.
- **SOSPECHOSO**: 15 puntos o más; o una sola señal media si el correo no pasó DMARC; o si pide la contraseña y trae enlaces, aunque pase DMARC (el atacante también puede autenticar su propio dominio). No cuenta si el correo viene de tu propio dominio (`--mi-dominio`) y pasó DMARC.
- **SIN INDICIOS CLAROS**: lo demás. No significa "seguro".

## Correos (`analizar`)

### ¿Quién lo envía de verdad?

| Código | Nivel | Cuándo salta |
|--------|-------|--------------|
| `AUTH-DMARC-FAIL` | Alto | Tu servidor comprobó que el remitente es falso (DMARC fail). Solo se lee la cabecera Authentication-Results de arriba: las de abajo las puede escribir el atacante. |
| `AUTH-COMPAUTH-FAIL` | Alto | Microsoft 365 no pudo verificar al remitente (`compauth=fail`). |
| `AUTH-FAIL` | Medio | SPF falla y no hay DKIM válido, sin resultado DMARC. |
| `AUTH-NONE` | Info | El archivo no trae cabeceras de autenticación (por ejemplo, cabeceras copiadas a mano). |
| `OWN-SPOOF` | Crítico | Finge venir de tu dominio y DMARC falló. |
| `REPLYTO-DIFF` | Alto / Medio | Las respuestas van a otro dominio. Se ignora en avisos de DocuSign, SharePoint, calendarios y similares, que responden a la persona real. |
| `FROM-DISPLAY` | Alto | El nombre visible muestra una dirección distinta de la real. |
| `FREEMAIL-ROLE` | Medio | "Gerente", "Contabilidad", "Banco"... escribiendo desde Gmail, Hotmail, etc. |
| `FROM-MIXED` / `FROM-PUNY` / `HOST-UNICODE` | Medio | Letras de otro alfabeto que se ven iguales que las latinas. |
| `FROM-MISSING` | Medio | No hay un remitente válido. |
| `MS-TENANT` | Medio | Se presenta como Microsoft desde una cuenta `*.onmicrosoft.com` cualquiera. |

### Suplantar a otros

| Código | Nivel | Cuándo salta |
|--------|-------|--------------|
| `BRAND-SPOOF` | Alto | El **nombre** del remitente es un banco, una entidad o una marca, pero el dominio no es suyo. No mira el asunto: "Reunión de Teams" o "Declaración DGI" son normales entre colegas. Si el remitente está autenticado, el nombre tiene que ser casi solo la marca ("Big Apple Imports" no imita a Apple). |
| `BRAND-LOOKALIKE` / `BRAND-LOOKALIKE-LINK` | Alto | Un dominio lleva el nombre de la marca sin ser suyo: `bgeneral-seguridad.com`, `bgeneral.net`. Solo cuentan como propios los dominios verificados de cada marca. |
| `BRAND-HOMOGLYPH` | Crítico | El dominio se escribe con letras cirílicas para verse igual que el del banco. |
| `LOOKALIKE` / `LOOKALIKE-REPLY` / `LOOKALIKE-LINK` | Alto | Imita tu dominio (`--mi-dominio`): una letra cambiada, `rn` por `m`, otra terminación, tu nombre con algo pegado. |
| `NAME-IN-LINK` | Medio | Tu nombre como subdominio de otro sitio: `miempresa-com.login-portal.xyz`. |
| `THREAD-LOOKALIKE` | Alto | Responde a una conversación con un proveedor, pero desde un dominio casi igual al suyo (no necesita `--mi-dominio`). |

Marcas incluidas: Banco General, Yappy, Banistmo, BAC Credomatic, Caja de Ahorros, Banco Nacional, entidades `.gob.pa`, Microsoft, Google, Apple, PayPal, Amazon, DHL, FedEx, Netflix, DocuSign, WhatsApp y Meta. Puedes añadir las tuyas con `--marcas archivo.txt`, una por línea: `Nombre|palabras clave|dominios oficiales`.

### Fraude sin virus

| Código | Nivel | Cuándo salta |
|--------|-------|--------------|
| `BEC-BANKCHANGE` | Alto | Habla de pagos y de una cuenta nueva, distinta, "la anterior fue cerrada"... |
| `BEC-GIFTCARD` | Medio / Alto | "¿Estás disponible?" + "no puedo atender llamadas" + tarjetas de regalo. Alto si viene de un correo gratuito. |
| `BEC-CONFIRMED` | Crítico | Lo anterior **y además** el remitente no es quien dice ser (otra dirección de respuesta, Gmail, dominio parecido, DMARC fail). |
| `TOAD-CALLBACK` | Medio / Alto | Sin enlaces: un cobro, un importe y un teléfono para "cancelar". |
| `TEXT-PAY` / `TEXT-CREDS` | Medio | Prisa ("urgente", "hoy mismo", "suspendida") junto a dinero o datos de acceso. Palabras como "expira" o "24 horas" solo cuentan si además hay una amenaza. |
| `CRED-LINK` | Alto | Prisa + datos de acceso + un enlace a un sitio que no es el del remitente. |
| `CRED-FREEHOST` | Medio | Pide datos de acceso con enlace a Google Forms, Canva, Notion, Wix... |
| `QR-CODE` | Medio / Alto | Pide escanear un código QR de una imagen o PDF y no trae enlaces. |
| `FAKE-REPLY` | Bajo | "RE:" sin ninguna conversación previa. |
| `TEXT-ZW` | Medio | Caracteres invisibles metidos entre las letras para esquivar filtros. |

### Enlaces

| Código | Nivel | Cuándo salta |
|--------|-------|--------------|
| `LINK-MISMATCH` | Alto | El texto muestra un sitio y el enlace lleva a otro. Con Safe Links de Microsoft, Proofpoint o Mimecast se compara con el destino real. Un nombre de archivo ("Cotización.xlsx") no cuenta como sitio. |
| `LINK-HIDDEN` | Bajo | El texto muestra otro sitio y el enlace pasa por un servicio de seguimiento de boletines (Mailchimp, SendGrid...) que esconde el destino. |
| `LINK-IP` / `LINK-USERINFO` / `LINK-SCRIPT` | Alto | Enlace a una IP, truco de la @ (`banco.com@malo.ru`), `javascript:` o `data:`. |
| `LINK-SHORT` / `LINK-PUNY` | Medio | Acortadores y dominios internacionales. |
| `OAUTH-CONSENT` | Alto | La página real de Microsoft o Google pidiendo permisos para una aplicación de otro. |
| `DEVICE-CODE` | Alto | Te manda a `microsoft.com/devicelogin` con un código. |
| `HTML-FORM` | Alto | Un formulario con campo de contraseña dentro del propio correo. |

Se buscan enlaces en `<a>`, `<area>`, los botones de Outlook (`<v:roundrect>`), el texto, las invitaciones `.ics` y los PDF adjuntos. Se revisan hasta 5000 enlaces por correo; si hay más, salta `LINKS-TRUNCATED`.

### Adjuntos

| Código | Nivel | Cuándo salta |
|--------|-------|--------------|
| `ATT-EXEC` | Crítico | `.exe`, `.js`, `.lnk`, `.vbs`, `.xll`, `.iqy`... (también `pago.exe.` con punto final). |
| `ATT-DOUBLE` | Crítico | `factura.pdf.exe`. |
| `ATT-RTLO` | Crítico | Carácter invisible que da la vuelta al nombre; se muestra como `<RTLO>`. |
| `ATT-DISK` | Alto | `.iso`, `.img`, `.vhd`: saltan las protecciones de Windows. |
| `ATT-HTML` | Alto | `.html`, `.svg`: abren páginas falsas o esconden descargas. |
| `ATT-MACRO` | Alto | Office con macros y OneNote. |
| `ATT-ENCRYPTED` | Alto | `.zip` con contraseña (el antivirus no puede mirarlo). Además se lee el nombre del primer archivo de dentro. |
| `ATT-ARCHIVE` | Bajo | Cualquier comprimido. |

Otros: `MIME-ABUSE` (estructura con demasiadas partes o anidamiento), `EMBEDDED` (trae otro correo adjunto, que también se revisa), `TEXT-TRUNCATED` (texto enorme, solo se revisó el principio).

## Dominios (`dominio`)

| Código | Nivel | Qué pasa |
|--------|-------|----------|
| `SPF-NONE`, `DMARC-NONE` | Alto | Cualquiera puede mandar correo como tu dominio. |
| `DMARC-P-NONE` | Alto | DMARC en `p=none`: observa pero no protege. |
| `SPF-PLUSALL`, `SPF-WIDE` | Crítico | `+all`, o rangos de IP enormes (`ip4:0.0.0.0/1`), o un `+all` escondido en un include. |
| `SPF-MULTI`, `DMARC-MULTI`, `SPF-ERROR`, `SPF-LOOKUPS` | Alto | Errores que hacen que los receptores ignoren el registro, incluido pasarse de 10 consultas DNS. |
| `MX-TAKEOVER` | Crítico | Tu servidor de correo está en un dominio que ya no existe: alguien podría registrarlo y recibir tu correo. |
| `MX-DEAD` | Alto / Medio | Los servidores de correo no existen. |
| `STS-MX-MISMATCH` | Alto | La política MTA-STS no incluye tus servidores: Gmail y Outlook pueden negarse a entregarte correo. |
| `PARKED-OPEN` | Alto | Dominio sin correo que se puede usar para suplantarte. |
| `DMARC-SP-NONE`, `DMARC-SYNTAX`, `DMARC-PCT0` | Medio | Subdominios sin proteger o políticas que en la práctica no se aplican. |
| `DKIM-NOTFOUND`, `SPF-NEUTRAL`, `SPF-NOALL`, `SPF-PTR`, `SPF-VOID`, `STS-BROKEN` | Medio | Configuración débil o rota. |
| `DMARC-QUARANTINE`, `DMARC-NORUA`, `DMARC-RUA-BAD`, `DMARC-RUA-AUTH`, `DMARC-PCT`, `DMARC-TESTING`, `DMARC-NP-NONE`, `DKIM-WEAK`, `DKIM-TESTING`, `SPF-LONG`, `SPF-LOOKUPS-NEAR`, `STS-TESTING`, `STS-BAD` | Bajo | Mejoras. |
| `STS-NONE`, `DNSSEC-NONE` | Info | Opcionales. |

Reglas generales: un fallo de DNS nunca se convierte en un problema del dominio (sale como "no se pudo comprobar" y código 2); un subdominio sin DMARC propio hereda el de su dominio principal usando `sp=`; con DMARC en `none` la nota no pasa de C.
