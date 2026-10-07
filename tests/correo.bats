#!/usr/bin/env bats
# Pruebas de correo-escudo. No usan la red: las respuestas DNS vienen de
# tests/fixtures/dns/dns.txt y los correos de tests/fixtures/correos/.
#   bats tests/correo.bats

setup() {
    S="$BATS_TEST_DIRNAME/../correo-escudo.sh"
    F="$BATS_TEST_DIRNAME/fixtures"
    export CORREO_ESCUDO_DNS_FILE="$F/dns/dns.txt"
    TMP="$(mktemp -d)"
}
teardown() { rm -rf "$TMP"; }

dom()  { "$S" dominio "$@" --format json; }
mail() { "$S" analizar "$F/correos/$1" "${@:2}" --format json; }

# --- Interfaz -------------------------------------------------------------------

@test "--version, --help y errores de uso (código 2)" {
    run "$S" --version; [ "$status" -eq 0 ]; [[ "$output" == correo-escudo\ v* ]]
    run "$S" --help;    [ "$status" -eq 0 ]; [[ "$output" == *"analizar"* ]]
    run "$S";                                 [ "$status" -eq 2 ]
    run "$S" nada;                            [ "$status" -eq 2 ]
    run "$S" dominio;                         [ "$status" -eq 2 ]
    run "$S" dominio 'a;reboot.com';          [ "$status" -eq 2 ]
    run "$S" dominio bueno.test --format xml; [ "$status" -eq 2 ]
    run "$S" dominio bueno.test --selector 'a b'; [ "$status" -eq 2 ]
    run "$S" analizar /no/existe.eml;         [ "$status" -eq 2 ]
    run "$S" analizar "$F/correos/legitimo.eml" --mi-dominio 'x;y'; [ "$status" -eq 2 ]
}

@test "un dominio que no existe es un error, no una nota" {
    run "$S" dominio noexiste.test
    [ "$status" -eq 2 ]; [[ "$output" == *"no existe"* ]]
}

# --- Dominio: SPF ----------------------------------------------------------------

@test "dominio bien configurado: nota A y código 0" {
    run dom bueno.test
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.grade == "A" and .score == 100 and .findings == []'
    echo "$output" | jq -e '.dmarc.policy == "reject" and .dkim[0].selector == "google" and .dkim[0].key == "2048"'
    echo "$output" | jq -e '.mta_sts == "enforce" and .tls_rpt == true and .dnssec == "yes"'
    echo "$output" | jq -e '.provider == "Google Workspace"'
}

@test "sin SPF ni DMARC: se puede suplantar (ALTO) y sugiere el SPF de su proveedor" {
    run dom malo.test
    [ "$status" -eq 1 ]
    echo "$output" | jq -e '[.findings[].id] | index("SPF-NONE") and index("DMARC-NONE")'
    echo "$output" | jq -e '.findings[] | select(.id=="SPF-NONE") | .fix | test("spf.protection.outlook.com")'
    echo "$output" | jq -e '.provider == "Microsoft 365"'
    run "$S" dominio malo.test --no-color
    [[ "$output" == *"cualquiera puede enviar correos"* ]]
}

@test "SPF +all es CRÍTICO; ptr está desaconsejado" {
    run dom debil.test
    echo "$output" | jq -e '.findings[0].id == "SPF-PLUSALL" and .findings[0].severity == "critical"'
    echo "$output" | jq -e '[.findings[].id] | index("SPF-PTR")'
    echo "$output" | jq -e '.grade == "F"'
}

@test "SPF: cuenta las consultas DNS recursivamente (límite de 10)" {
    run dom lookups.test
    echo "$output" | jq -e '.spf.dns_lookups > 10'
    echo "$output" | jq -e '.findings[] | select(.id=="SPF-LOOKUPS") | .severity == "high"'
}

@test "SPF y DMARC duplicados dan error (permerror)" {
    run dom roto.test
    echo "$output" | jq -e '[.findings[].id] | index("SPF-MULTI") and index("DMARC-MULTI")'
}

@test "SPF: include a dominios sin SPF y mecanismos inválidos" {
    run dom incluye.test
    echo "$output" | jq -e '[.findings[] | select(.id=="SPF-ERROR")] | length == 1'
    echo "$output" | jq -e '.findings[] | select(.id=="SPF-ERROR") | .title | test("noexiste.test") and test("sinspf.test") and test("foo:bar")'
}

# --- Dominio: DMARC y DKIM --------------------------------------------------------

@test "DMARC p=none no protege; pct y falta de informes se avisan" {
    run dom debil.test
    echo "$output" | jq -e '[.findings[].id] | index("DMARC-P-NONE") and index("DMARC-PCT") and index("DMARC-NORUA")'
}

@test "DMARC quarantine con sp=none: los subdominios quedan expuestos" {
    run dom debil2.test
    echo "$output" | jq -e '[.findings[].id] | index("DMARC-SP-NONE") and index("DMARC-QUARANTINE")'
}

@test "un subdominio hereda el DMARC de su dominio principal (RFC 9989)" {
    run dom ventas.empresa.test
    echo "$output" | jq -e '.dmarc.inherited_from == "empresa.test" and .dmarc.policy == "reject"'
    echo "$output" | jq -e '[.findings[].id] | index("DMARC-NONE") == null'
}

@test "DKIM: mide la llave (1024 = débil), detecta t=y y acepta ed25519" {
    run dom debil.test
    echo "$output" | jq -e '.dkim[0].key == "1024"'
    echo "$output" | jq -e '[.findings[].id] | index("DKIM-WEAK") and index("DKIM-TESTING")'
    run dom ventas.empresa.test --selector s1
    echo "$output" | jq -e '.dkim[0].key == "ed25519"'
}

@test "DKIM no encontrado: pide el selector y explica cómo activarlo en Microsoft 365" {
    run dom malo.test
    echo "$output" | jq -e '.findings[] | select(.id=="DKIM-NOTFOUND") | .fix | test("--selector") and test("security.microsoft.com")'
}

# --- Dominio: casos especiales -------------------------------------------------------

@test "dominio sin correo: se exige blindarlo (SPF -all, DMARC reject, MX nulo)" {
    run dom parqueado.test
    echo "$output" | jq -e '.findings[] | select(.id=="PARKED-OPEN") | .fix | test("v=spf1 -all") and test("0 \\.")'
    run dom blindado.test
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.grade == "A" and ([.findings[] | select(.severity != "info")] | length == 0)'
}

@test "un fallo de DNS NO se convierte en 'no tienes DMARC' (código 2, incompleto)" {
    run dom falla.test
    [ "$status" -eq 2 ]
    echo "$output" | jq -e '.incomplete | index("DMARC (SERVFAIL)")'
    echo "$output" | jq -e '[.findings[].id] | index("DMARC-NONE") == null'
    run "$S" dominio falla.test --no-color
    [[ "$output" == *"no se pudo comprobar todo"* ]]
}

@test "MTA-STS sin política publicada es un error de configuración" {
    run dom mtsrota.test
    echo "$output" | jq -e '[.findings[].id] | index("STS-BROKEN")'
    run dom mtsrota.test --no-https
    echo "$output" | jq -e '[.findings[].id] | index("STS-BROKEN") == null'
}

@test "registros DNS manipulados no ejecutan nada y el JSON sigue siendo válido" {
    run dom inyeccion.test
    echo "$output" | jq -e . >/dev/null
    [ ! -e /reboot ]
    echo "$output" | jq -e '[.findings[].id] | index("SPF-ERROR")'
}

@test "lista: revisa varios dominios y sigue aunque uno falle" {
    printf 'bueno.test\nmalo.test  # cliente 2\n\nnoexiste.test\n' > "$TMP/l.txt"
    run "$S" lista "$TMP/l.txt"
    [ "$status" -eq 1 ]
    [[ "$output" == *"bueno.test"*"A (100)"* ]]
    [[ "$output" == *"malo.test"*"SPF-NONE"* ]]
    [[ "$output" == *"noexiste.test"*"no existe"* ]]
}

@test "el informe se guarda con permisos 600 y se niega a seguir enlaces simbólicos" {
    run "$S" dominio bueno.test -o "$TMP/r.txt"
    [ "$(stat -c %a "$TMP/r.txt")" = "600" ]
    ! grep -q $'\e' "$TMP/r.txt"
    echo x > "$TMP/victima"; ln -s "$TMP/victima" "$TMP/enlace"
    run "$S" dominio bueno.test -o "$TMP/enlace"
    [ "$status" -eq 2 ]; [ "$(cat "$TMP/victima")" = x ]
}

# --- Correos: phishing ---------------------------------------------------------------

@test "phishing de banco: marca suplantada, enlace engañoso a una IP" {
    run mail phishing-banco.eml
    [ "$status" -eq 3 ]      # 3 = PELIGROSO
    echo "$output" | jq -e '.verdict == "PELIGROSO"'
    echo "$output" | jq -e '[.findings[].id] | index("BRAND-SPOOF") and index("LINK-MISMATCH") and index("LINK-IP") and index("CRED-LINK")'
    echo "$output" | jq -e '.subject == "Aviso urgente: su cuenta ha sido suspendida"'
}

@test "fraude del jefe: Gmail, responder a otra dirección y cambio de cuenta bancaria" {
    run mail fraude-jefe.eml
    echo "$output" | jq -e '.verdict == "PELIGROSO"'
    echo "$output" | jq -e '[.findings[].id] | index("BEC-BANKCHANGE") and index("REPLYTO-DIFF") and index("FREEMAIL-ROLE") and index("FAKE-REPLY") and index("BEC-CONFIRMED")'
    echo "$output" | jq -e '.from_name == "Carlos Pérez - Gerente General"'
}

@test "adjuntos peligrosos: doble extensión, RTLO, SVG, ISO y nombres codificados" {
    run mail adjuntos.eml
    echo "$output" | jq -e '[.findings[].id] | index("ATT-DOUBLE") and index("ATT-RTLO") and index("ATT-HTML") and index("ATT-DISK") and index("ATT-EXEC")'
    echo "$output" | jq -e '[.attachments[].name] | index("Mensaje de voz (0:42).svg") and index("documentos envío.iso")'
    # El carácter invisible RTLO se muestra, no se interpreta
    echo "$output" | jq -e '.attachments[] | select(.name | test("RTLO")) | .name == "Factura_<RTLO>fdp.exe"'
    echo "$output" | jq -e '[.findings[].id] | index("AUTH-DMARC-FAIL")'
}

@test "solo vale la cabecera de autenticación de ARRIBA (la de abajo puede ser falsa)" {
    run mail auth-falsa.eml --mi-dominio empresa-demo.com.pa
    echo "$output" | jq -e '.authentication.dmarc == "fail"'
    echo "$output" | jq -e '[.findings[].id] | index("OWN-SPOOF") and index("NAME-IN-LINK")'
}

@test "dominio parecido al de la empresa y trucos en los enlaces" {
    run mail dominio-parecido.eml --mi-dominio ferreteria-pacifico.com.pa
    echo "$output" | jq -e '[.findings[].id] | index("LOOKALIKE") and index("LOOKALIKE-LINK") and index("LINK-USERINFO") and index("LINK-SHORT") and index("LINK-PUNY") and index("LINK-SCRIPT")'
    # Sin --mi-dominio no puede saber cuál es "tu" dominio
    run mail dominio-parecido.eml
    echo "$output" | jq -e '[.findings[].id] | index("LOOKALIKE") == null'
}

@test "correo legítimo: sin indicios y código 0" {
    run mail legitimo.eml
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.verdict == "SIN INDICIOS CLAROS" and .findings == []'
}

@test "los enlaces se muestran desactivados (hxxp, [.])" {
    run "$S" analizar "$F/correos/phishing-banco.eml" --no-color
    [[ "$output" == *"hxxp://185[.]231[.]44[.]17"* ]]
    [[ "$output" != *"http://185.231"* ]]
    run mail phishing-banco.eml
    echo "$output" | jq -e '.links[0].url_defanged | startswith("hxxp://")'
}

@test "correo hostil: sin secuencias de escape en la salida y JSON válido" {
    run "$S" analizar "$F/correos/hostil.eml" --no-color
    ! grep -q $'\e' <<< "$output"
    ! grep -q $'\a' <<< "$output"
    [[ "$output" == *"FROM-DISPLAY"* ]]
    run mail hostil.eml
    echo "$output" | jq -e . >/dev/null
}

@test "rechaza archivos .msg de Outlook con una explicación" {
    printf '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1resto' > "$TMP/x.msg"
    run "$S" analizar "$TMP/x.msg"
    [ "$status" -eq 2 ]; [[ "$output" == *".eml"* ]]
}

@test "marcas extra de la empresa (--marcas) y validación del archivo" {
    printf 'Mi Proveedor|proveedor xyz|proveedorxyz.com\n' > "$TMP/m.txt"
    printf 'From: "Proveedor XYZ" <pagos@xyz-pagos.net>\nSubject: hola\n\nhola\n' > "$TMP/p.eml"
    run "$S" analizar "$TMP/p.eml" --marcas "$TMP/m.txt" --format json
    echo "$output" | jq -e '[.findings[].id] | index("BRAND-SPOOF")'
    printf 'malo\n' > "$TMP/m2.txt"
    run "$S" analizar "$TMP/p.eml" --marcas "$TMP/m2.txt"
    [ "$status" -eq 2 ]
}

@test "rendimiento: un correo de 5 MB se analiza en menos de 30 segundos" {
    { printf 'From: a@b.test\nSubject: grande\nContent-Type: text/html\n\n'
      for i in $(seq 1 40000); do printf '<p>linea %d <a href="https://ejemplo.test/%d">x</a></p>\n' "$i" "$i"; done; } > "$TMP/g.eml"
    run timeout 30 "$S" analizar "$TMP/g.eml" --format json
    echo "$output" | jq -e . >/dev/null
}

# --- Casos de la revisión independiente (cada uno fue un fallo real) ------------------

@test "revisión: la dirección del atacante no puede fingir 'dmarc=pass' en la autenticación" {
    run mail revision/auth-inyectada.eml --mi-dominio empresa-demo.com.pa
    echo "$output" | jq -e '.authentication.dmarc == "fail" and .verdict == "PELIGROSO"'
    echo "$output" | jq -e '[.findings[].id] | index("OWN-SPOOF")'
}

@test "revisión: adjuntos con nombre partido (RFC 2231), punto o espacio al final" {
    run mail revision/adjuntos-trucos.eml
    echo "$output" | jq -e '.verdict == "PELIGROSO" and ([.findings[].id] | index("ATT-EXEC"))'
    echo "$output" | jq -e '[.attachments[].name] | index("factura_2026.exe")'
}

@test "revisión: un correo reenviado como adjunto (message/rfc822) también se revisa" {
    run mail revision/reenviado.eml
    echo "$output" | jq -e '[.findings[].id] | index("ATT-DOUBLE") and index("EMBEDDED")'
}

@test "revisión: enlaces con HREF en mayúsculas, saltos de línea y entidades HTML" {
    run mail revision/enlace-multilinea.eml
    echo "$output" | jq -e '.links | length >= 1'
    echo "$output" | jq -e '[.findings[].id] | index("LINK-IP")'
    run mail revision/enlaces-codificados.eml
    echo "$output" | jq -e '.links | length == 3'
}

@test "revisión: correo en Latin-1 (iso-8859-1) con tildes" {
    run mail revision/latin1.eml
    echo "$output" | jq -e '[.findings[].id] | index("TEXT-CREDS")'
    echo "$output" | jq -e '.verdict == "SOSPECHOSO"'
}

@test "revisión: banco solo en el texto y enlace a un dominio que imita al banco" {
    run mail revision/banco-en-cuerpo.eml
    echo "$output" | jq -e '[.findings[].id] | index("BRAND-LOOKALIKE-LINK")'
    echo "$output" | jq -e '.verdict != "SIN INDICIOS CLAROS"'
}

@test "revisión: letras cirílicas que imitan 'Banco General' en el nombre" {
    run mail revision/cirilico.eml
    echo "$output" | jq -e '[.findings[].id] | index("BRAND-SPOOF") and index("FROM-MIXED")'
}

@test "revisión: correos normales de empresa NO se marcan (Teams, DGI, Yappy, boletines, Safe Links, Mailchimp)" {
    for f in "$F"/correos/legitimos/*.eml; do
        run "$S" analizar "$f" --format json
        echo "$f: $output" | head -c 400
        echo "$output" | jq -e '.verdict == "SIN INDICIOS CLAROS"'
        echo "$output" | jq -e '[.findings[] | select(.severity == "high" or .severity == "critical")] | length == 0'
    done
}

@test "revisión: cabeceras enormes y miles de <a> sin enlace no cuelgan el análisis" {
    { printf 'From: "%s" <x@evil.test>\nReply-To: %s\nSubject: a\nContent-Type: text/html\n\n' "$(head -c 300000 /dev/zero | tr '\0' a)" "$(head -c 200000 /dev/zero | tr '\0' b)"
      for i in $(seq 1 30000); do printf '<a name="x%d">y</a>' "$i"; done; echo; } > "$TMP/lento.eml"
    run timeout 20 "$S" analizar "$TMP/lento.eml" --format json
    [ "$status" -ne 124 ]
    echo "$output" | jq -e . >/dev/null
}

@test "revisión: bytes inválidos y controles C1 no llegan a la salida (JSON UTF-8 válido)" {
    printf 'From: a@b.test\nSubject: Pago \xff\xc2\x9b0;titulo\nContent-Type: text/plain\n\nhola\n' > "$TMP/j.eml"
    run "$S" analizar "$TMP/j.eml" --format json
    echo "$output" | jq -e . >/dev/null
    ! printf '%s' "$output" | grep -q $'\xc2\x9b'
    printf '%s' "$output" | iconv -f UTF-8 -t UTF-8 >/dev/null
}

@test "revisión: un fallo de DNS no acusa al dominio (nota ?, sin PARKED-OPEN)" {
    run dom parq.test
    [ "$status" -eq 2 ]
    echo "$output" | jq -e '.grade == "?" and ([.findings[].id] | index("PARKED-OPEN") == null)'
    echo "$output" | jq -e '.summary | test("No se pudo comprobar")'
}

@test "revisión: un subdominio que hereda sp=none no está protegido" {
    run dom pagos.org.test
    echo "$output" | jq -e '.dmarc.policy == "none" and ([.findings[].id] | index("DMARC-P-NONE"))'
}

@test "revisión: un include repetido cuenta sus consultas otra vez" {
    run dom dup.test
    echo "$output" | jq -e '.spf.dns_lookups > 10 and ([.findings[].id] | index("SPF-LOOKUPS"))'
}

@test "revisión: DNS caído en un selector DKIM = incompleto, no 'sin DKIM'" {
    run dom dk.test
    [ "$status" -eq 2 ]
    echo "$output" | jq -e '[.findings[].id] | index("DKIM-NOTFOUND") == null'
}

@test "revisión: pct=0 y DMARC sin p= cuentan como p=none" {
    run dom pct.test
    echo "$output" | jq -e '.dmarc.policy == "none" and ([.findings[].id] | index("DMARC-PCT0"))'
    run dom nop.test
    echo "$output" | jq -e '.dmarc.policy == "none" and ([.findings[].id] | index("DMARC-SYNTAX"))'
}

@test "revisión: lista con todos los dominios fallidos termina con código 2 y admite JSON" {
    printf 'parq.test\nnoexiste.test\n' > "$TMP/l.txt"
    run "$S" lista "$TMP/l.txt"
    [ "$status" -eq 2 ]
    run "$S" lista "$TMP/l.txt" --format json
    echo "$output" | jq -e '.domains | length == 2'
}

@test "revisión 2: comillas dentro de comentarios no permiten fingir el resultado" {
    run mail revision/auth-comillas.eml
    echo "$output" | jq -e '.authentication.dmarc != "pass" and .authentication.dkim == "fail"'
    echo "$output" | jq -e '.verdict != "SIN INDICIOS CLAROS"'
}

@test "revisión 2: una cabecera de autenticación muy larga no esconde el DMARC fail" {
    run mail revision/auth-larga.eml --mi-dominio empresa-demo.com.pa
    echo "$output" | jq -e '.authentication.dmarc == "fail" and .verdict == "PELIGROSO"'
}

@test "revisión 2: formato de Microsoft 365 (sin nombre de servidor) y compauth" {
    run mail revision/auth-m365.eml
    echo "$output" | jq -e '.authentication.spf == "fail" and .authentication.dmarc == "none"'
    echo "$output" | jq -e '[.findings[].id] | index("AUTH-COMPAUTH-FAIL")'
}

@test "revisión 2: texto engañoso en enlaces anidados o sin cerrar" {
    run mail revision/enlace-anidado.eml
    echo "$output" | jq -e '[.findings[].id] | index("LINK-MISMATCH")'
    run mail revision/enlace-sin-cerrar.eml
    echo "$output" | jq -e '[.findings[].id] | index("LINK-MISMATCH")'
}

@test "revisión 3: un dominio con el nombre del banco en otra terminación (bgeneral.net) NO es del banco" {
    printf 'From: Banco General <alertas@bgeneral.net>\nSubject: Aviso\nContent-Type: text/html\n\n<a href="https://www.bgeneral.net/x">Ver</a>\n' > "$TMP/b.eml"
    run "$S" analizar "$TMP/b.eml" --format json
    echo "$output" | jq -e '[.findings[].id] | index("BRAND-SPOOF") and index("BRAND-LOOKALIKE")'
}

@test "revisión 2: un servicio de seguimiento no esconde un enlace que dice ser de otro sitio" {
    run mail revision/seguimiento-oculto.eml
    echo "$output" | jq -e '[.findings[].id] | index("LINK-HIDDEN")'
}

@test "revisión 2: los dominios propios de una marca con otra terminación no son imitaciones" {
    for d in bgeneral.com.pa banistmo.com.pa credomatic.com netflix.net fedex.com.pa paypal-communication.com microsoftstore.com; do
        printf 'Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\nFrom: Aviso <info@%s>\nSubject: Novedades\nContent-Type: text/html\n\n<a href="https://www.%s/x">Ver</a>\n' "$d" "$d" > "$TMP/m.eml"
        run "$S" analizar "$TMP/m.eml" --format json
        echo "$d: $output" | head -c 300
        echo "$output" | jq -e '[.findings[].id] | (index("BRAND-LOOKALIKE") == null) and (index("BRAND-LOOKALIKE-LINK") == null)'
    done
}

# --- Auditoría v1.1: amenazas de 2026 -------------------------------------------------

@test "auditoría: cada amenaza de 2026 se detecta (QR, llamada, BEC, OAuth, zip con clave, hilo secuestrado...)" {
    while IFS='|' read -r f id; do
        run "$S" analizar "$F/correos/auditoria/$f" --format json
        echo "$f -> $output" | head -c 300; echo
        echo "$output" | jq -e --arg id "$id" '([.findings[].id] | index($id)) and .verdict != "SIN INDICIOS CLAROS"'
    done <<'EOF'
01-quishing-png.eml|QR-CODE
02-callback-toad.eml|TOAD-CALLBACK
03-bec-variante.eml|BEC-BANKCHANGE
04-entidades-html.eml|TEXT-CREDS
06-zip-clave.eml|ATT-ENCRYPTED
11-oauth-devicecode.eml|OAUTH-CONSENT
12-servicios-legitimos.eml|CRED-FREEHOST
13-hilo-secuestrado.eml|THREAD-LOOKALIKE
14-ics.eml|LINK-IP
15-html-sin-a.eml|HTML-FORM
16-homoglifo-utf8.eml|BRAND-HOMOGLYPH
18-bec-ia.eml|BEC-GIFTCARD
19-adjuntos-varios.eml|ATT-EXEC
EOF
}

@test "auditoría: el .exe escondido dentro de un .zip también se ve" {
    run mail auditoria/06-zip-clave.eml
    echo "$output" | jq -e '[.findings[].id] | index("ATT-EXEC")'
}

@test "auditoría: 300 enlaces inocentes delante no esconden el enlace malo" {
    { printf 'From: Banco <x@ejemplo.test>\nSubject: hola\nContent-Type: text/html\n\n'
      for i in $(seq 1 400); do printf '<a href="https://ejemplo.test/%d">x</a>\n' "$i"; done
      printf '<a href="http://185.1.2.3/login">https://www.bgeneral.com/login</a>\n'; } > "$TMP/cola.eml"
    run "$S" analizar "$TMP/cola.eml" --format json
    echo "$output" | jq -e '[.findings[].id] | index("LINK-IP") and index("LINK-MISMATCH")'
}

@test "auditoría: SPF con rangos enormes o +all escondido en un include es CRÍTICO" {
    run dom ancho.test
    echo "$output" | jq -e '.findings[0].id == "SPF-WIDE" and .findings[0].severity == "critical"'
}

@test "auditoría: MX que no existe (y cuyo dominio está libre) y MTA-STS que no lo incluye" {
    run dom mxmuerto.test
    echo "$output" | jq -e '[.findings[].id] | index("MX-TAKEOVER") and index("MX-DEAD") and index("STS-MX-MISMATCH")'
}

@test "auditoría: informes DMARC sin mailto: o a otro dominio que no los acepta" {
    run dom ruaext.test
    echo "$output" | jq -e '[.findings[].id] | index("DMARC-RUA-AUTH") and index("DMARC-RUA-BAD")'
}

@test "auditoría: p=none es ALTO (el código de salida avisa) y el arreglo de SPF se puede copiar tal cual" {
    printf 'nop2.test SOA x\nnop2.test MX 10 mail.nop2.test.\nmail.nop2.test A 192.0.2.25\n_dmarc.nop2.test TXT v=DMARC1; p=none\n' > "$TMP/d.txt"
    CORREO_ESCUDO_DNS_FILE="$TMP/d.txt" run "$S" dominio nop2.test --format json
    [ "$status" -eq 1 ]
    echo "$output" | jq -e '.findings[] | select(.id=="SPF-NONE") | .fix | test("valor: v=spf1 mx -all")'
}

# --- Uso en empresas: lotes, SIEM, privacidad ------------------------------------------

@test "lotes: varios correos o una carpeta, en texto o JSON Lines (una línea por correo)" {
    run "$S" analizar "$F/correos/legitimo.eml" "$F/correos/fraude-jefe.eml" --no-color
    [ "$status" -eq 3 ]
    [[ "$output" == *"SIN INDICIOS CLAROS"*"legitimo.eml"* ]]
    [[ "$output" == *"PELIGROSO"*"fraude-jefe.eml"* ]]
    run "$S" analizar "$F/correos" --format json
    [ "$(grep -c . <<< "$output")" -ge 7 ]
    while IFS= read -r l; do echo "$l" | jq -e '.verdict_code' >/dev/null; done <<< "$output"
}

@test "lotes: un archivo que no es un correo no detiene el lote (y da error 2 si no hay nada peor)" {
    echo hola > "$TMP/no.eml"
    run "$S" analizar "$TMP/no.eml" "$F/correos/legitimo.eml" --no-color
    [ "$status" -eq 2 ]
    [[ "$output" == *"ERROR"*"no parece un correo"* ]]
}

@test "entrada estándar: cat correo.eml | correo-escudo analizar -" {
    run bash -c "cat '$F/correos/phishing-banco.eml' | '$S' analizar - --format json"
    [ "$status" -eq 3 ]
    echo "$output" | jq -e '.file == "(entrada estándar)" and .verdict == "PELIGROSO"'
}

@test "JSON para SIEM: schema_version, verdict_code, fecha ISO, Message-ID, IP, URL completa y SHA-256" {
    run mail adjuntos.eml
    echo "$output" | jq -e '.schema_version == 2 and .verdict_code == "dangerous"'
    echo "$output" | jq -e '.date_iso == "2026-10-07T07:45:00-05:00"'
    echo "$output" | jq -e '.attachments[0].sha256 | test("^[0-9a-f]{64}$")'
    exp=$(printf 'MZ fake executable content %.0s' $(seq 1 20) | sha256sum | cut -c1-64)
    echo "$output" | jq -e --arg h "$exp" '.attachments[0].sha256 == $h'
    run mail phishing-banco.eml
    echo "$output" | jq -e '.message_id == "a1b2c3@bgeneral-seguridad.com" and .sender_ip == "45.88.12.9"'
    echo "$output" | jq -e '.links[0].url | startswith("http://185.231.44.17")'
    echo "$output" | jq -e '.findings[0].points > 0'
}

@test "--anonimizar: sin nombres, asunto ni parte local de las direcciones" {
    run mail fraude-jefe.eml --anonimizar
    echo "$output" | jq -e '.from_name == "[oculto]" and .subject == "[oculto]" and .file == "[oculto]"'
    echo "$output" | jq -e '.from_address == "***@gmail.com"'
    ! grep -q 'carlos' <<< "$output"
}

@test "--fail-on critical: un SOSPECHOSO no hace fallar el código de salida" {
    run "$S" analizar "$F/correos/revision/latin1.eml" --fail-on critical
    [ "$status" -eq 0 ]
}

# --- Funciones internas -----------------------------------------------------------------

@test "valid_domain rechaza lo que no es un dominio" {
    source "$S"
    valid_domain empresa.com.pa; valid_domain _dmarc.empresa.com; valid_domain xn--caf-dma.com
    ! valid_domain 'a;b.com'; ! valid_domain '-a.com'; ! valid_domain 'com'; ! valid_domain 'a..com'
}
