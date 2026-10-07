# Seguridad

## Si encontraste un fallo

Si das con un correo que engaña al programa (sale LIMPIO siendo phishing, lo cuelga, o hace que muestre algo que no debería), avísame por **Security → Report a vulnerability** en GitHub. Así queda privado hasta que esté arreglado. Contesto en una semana como mucho.

Si puedes, manda el `.eml` mínimo que lo provoca. Bórrale antes nombres, correos y datos reales: no los necesito.

Un falso positivo (un correo bueno marcado como sospechoso) no es una vulnerabilidad. Ábrelo como issue normal.

## Lo que el programa promete

- **No toca nada.** `dominio` solo pregunta al DNS público y, si tu dominio tiene MTA-STS, descarga esa política. `analizar` no se conecta a internet: no abre enlaces, no descarga imágenes, no ejecuta adjuntos.
- **Trata el correo como enemigo.** Todo lo que viene del correo se limpia antes de mostrarlo: caracteres invisibles, texto escrito al revés (RTLO) y códigos de control. Los enlaces se muestran desactivados (`hxxps`, `[.]`) para que nadie haga clic sin querer.
- **Solo cree a tu servidor.** De las cabeceras de autenticación solo cuenta la de arriba, que es la que puso tu servidor de correo. Las de abajo las pudo escribir cualquiera.
- **Si no sabe, lo dice.** Si el DNS no responde, el resultado es "incompleto". Nunca te dirá "no tienes DMARC" por un fallo de red.
- **No se cuelga con correos trampa.** Hay límites de tamaño, partes y enlaces, y cuando se alcanzan lo avisa.
- **Tus informes son tuyos.** Se guardan con permisos 600 y no sigue enlaces simbólicos, para que nadie le haga escribir donde no debe.

## Lo que no promete

No es un antivirus ni reemplaza el filtro de tu correo. Mira señales; un atacante con un dominio limpio y un texto bien escrito puede pasar. Por eso el informe dice "no encontré señales", nunca "es seguro".
