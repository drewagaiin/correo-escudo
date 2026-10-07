# Cambios

Aquí se apunta qué cambió en cada versión y por qué. Si algo te rompió un script, búscalo en "Ojo si automatizas".

## [1.1.0] - 2026-10-07

Esta versión salió de una auditoría pedida a propósito: revisar el programa como lo haría un equipo de seguridad antes de meterlo en una empresa. Se hizo en varias vueltas, cada una con otra mirada (alguien que intenta romperlo, alguien que busca correos de phishing que se le escapen y alguien que lo tiene que usar un lunes a las 8 de la mañana). Las revisiones las hicieron agentes de IA y cada hallazgo se comprobó con un correo o un registro DNS de prueba antes de corregirlo.

### Ojo si automatizas
- `analizar` ahora devuelve **3** cuando el veredicto es PELIGROSO (antes era 1). Sigue: 0 limpio, 1 sospechoso, 2 error.
- `--fail-on` ahora también funciona con `analizar`.
- El JSON lleva `schema_version: 2`. Se añadieron campos; ninguno cambió de nombre.
- `p=none` en DMARC ahora sale como riesgo **alto**, no medio. Tu nota puede bajar: es a propósito, `none` no detiene a nadie.

### Lo que se cerró (seguridad del propio programa)
- Un correo con cientos de partes anidadas podía dejar el análisis colgado. Ahora cada parte se encuentra al instante y hay topes: 50 niveles, 2000 partes, 3 MB de texto.
- Un correo con más de 5000 enlaces podía esconder el malo al final. Ahora se avisa con `LINKS-TRUNCATED` en vez de callar.
- Correos en Latin-1 muy grandes tardaban demasiado al convertirse.
- `lista` podía terminar en 0 aunque un dominio fallara por dentro.
- Si no se podía escribir el informe, el error se perdía.
- Un registro TXT con bytes nulos ensuciaba la salida; ahora se ven como `?`.
- Un `.digrc` o `.curlrc` del usuario podía cambiar cómo se consulta el DNS; ahora se ignoran.
- Recortar textos con tildes ya no parte letras por la mitad.

### Lo que ahora detecta
- Cambio de cuenta bancaria de un proveedor, pedido de tarjetas de regalo y, cuando se juntan varias señales, `BEC-CONFIRMED`.
- Estafas por llamada (TOAD): "llama a este número para cancelar".
- Códigos QR para escanear sin ningún enlace en el correo (quishing).
- Phishing de consentimiento OAuth y de código de dispositivo de Microsoft.
- Formularios HTML dentro del correo que piden la clave.
- Hilos secuestrados: te responden en una conversación real pero desde un dominio parecido.
- Zips cifrados (la contraseña viene en el texto para que el antivirus no lo abra).
- Enlaces dentro de PDFs y de invitaciones de calendario `.ics`.
- Imitación de marcas comparando con sus dominios reales, incluidas letras cirílicas.
- En dominios: SPF que autoriza rangos enormes, includes con `+all`, servidores MX que ya no existen (o que alguien podría registrar), MTA-STS que no coincide con tus MX, informes DMARC enviados a un dominio de fuera sin autorización.

### Lo que dejó de molestar (falsos positivos)
- Archivos compartidos por SharePoint/OneDrive.
- DocuSign con Reply-To distinto.
- Avisos de "no se pudo entregar" de Microsoft 365.
- Empresas que se llaman parecido a una marca grande.
- Palabras como "hoy" o "pronto" ya no cuentan como presión por sí solas.

### Para el día a día
- Varios correos a la vez: `analizar *.eml`, una carpeta entera o `-` para leer de la entrada. En JSON sale una línea por correo, lista para un SIEM.
- `--anonimizar` tapa nombres y correos para compartir el informe sin datos personales (Ley 81).
- `--detalle` muestra técnicas MITRE ATT&CK y puntos de cada señal.
- El informe del correo termina con "Qué hacer", en pasos.
- El informe del dominio muestra dónde está gestionado tu DNS y cómo deberían quedar tus registros, listos para copiar.
- Nuevo `QUE-HAGO.md` para quien recibe el correo, no para el técnico.
- El JSON ahora trae fecha ISO, Message-ID, IP del remitente, URL completa y SHA-256 de cada adjunto.

## [1.0.0] - 2026-10-07

Primera versión.

- `dominio`: revisa SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC y MX nulo; da una nota de A a F y te dice cómo arreglarlo según tu proveedor.
- `lista`: muchos dominios en una tabla o JSON.
- `analizar`: busca phishing en un `.eml` sin usar internet.
- Antes de publicarla pasó 3 rondas de revisión con 25 fallos corregidos: se podía fingir `dmarc=pass`, cabeceras gigantes la colgaban, algunos adjuntos peligrosos se escapaban y un fallo de DNS se confundía con "no tienes DMARC".
