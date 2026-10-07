# Me llegó un correo raro. ¿Qué hago?

Esta página es para la persona que recibe el correo, no para el técnico.

## Antes de nada

- **No hagas clic** en los enlaces ni abras los adjuntos.
- Si el correo te pide **pagar, cambiar una cuenta bancaria o comprar tarjetas de regalo**, llama a quien supuestamente lo envía a un número que ya tenías guardado. Nunca al número que viene en el correo. Esa llamada de un minuto es la mejor protección que existe contra el fraude del jefe.

## Revisarlo con correo-escudo

1. Guarda el correo como archivo:
   - **Gmail**: abre el correo, pulsa los tres puntos ⋮ arriba a la derecha y elige *Descargar mensaje*.
   - **Outlook en el navegador** (outlook.office.com): ⋯ → *Guardar como*.
   - **Outlook de escritorio**: guarda archivos `.msg`, que no sirven. Abre el mismo correo en outlook.office.com y descárgalo desde ahí.
2. Ejecuta (o pídele a tu técnico que ejecute):

   ```bash
   ./correo-escudo.sh analizar ~/Downloads/el-correo.eml --mi-dominio tuempresa.com
   ```

   En Windows con WSL la carpeta de descargas es `/mnt/c/Users/TU_USUARIO/Downloads/`.

3. Lee el veredicto:

   | Dice | Qué significa | Qué hacer |
   |------|---------------|-----------|
   | **PELIGROSO** | Tiene señales claras de fraude | Bórralo y avisa a quien te lleva el correo |
   | **SOSPECHOSO** | Hay cosas raras | Confírmalo por teléfono antes de hacer lo que pide |
   | **SIN INDICIOS CLAROS** | No se vio nada raro | Igual: si pide dinero o contraseñas, confírmalo |

## Si ya caíste

- **Pusiste tu contraseña**: cámbiala ahora mismo, desde otro equipo si puedes, y activa la verificación en dos pasos.
- **Hiciste una transferencia**: llama a tu banco ya mismo y pide que intenten frenar o reversar la transferencia (ACH). Después pon la denuncia en el Ministerio Público. En estos casos las primeras horas son las que cuentan.
- **Abriste un adjunto**: desconecta el equipo de la red (wifi y cable) y avisa a tu técnico antes de seguir usándolo.

## Reportarlo

- **Outlook**: botón *Informar* → *Phishing*.
- **Gmail**: ⋮ → *Denunciar phishing*.

Así tu proveedor de correo aprende y bloquea correos parecidos para todos.
