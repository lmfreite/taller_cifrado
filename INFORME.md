# Informe técnico: mensajería segura

## 1. Diseño y algoritmos

El programa implementa el envío de un mensaje de Ana a Luis. Ana firma el texto en UTF-8 con RSA-PSS y SHA-256. El contenido, su huella SHA-256 y la firma se serializan en JSON canónico y se cifran con AES-256-GCM usando una clave y un nonce nuevos para cada envío. La clave de sesión se envuelve con RSA-OAEP y SHA-256 usando la clave pública del destinatario. El sobre incluye la identidad de ambas partes y el certificado del emisor; estos campos se vinculan al cifrado como datos asociados autenticados (AAD).

Al recibir, Luis valida la cadena y vigencia de ambos certificados, descifra la clave de sesión y el contenido, compara el hash y verifica la firma con la clave del certificado de Ana. El certificado del emisor no se confía por venir adjunto: se verifica con el certificado de CA local que Luis ya tiene configurado.

La interfaz web presenta laboratorios independientes para SHA-256/avalancha, AES-GCM con clave/nonce/ciphertext/etiqueta, cifrado híbrido AES/RSA, firma y verificación con mensaje alterado, y validación de certificados válidos, no confiables y vencidos. También permite inspeccionar por usuario el par RSA y su certificado X.509. Al solicitarlo, el inspector revela la clave privada PEM con un aviso; esto es exclusivamente para la demostración local. El flujo integrado añade una traza del envío con hash, firma, nonce, clave de sesión envuelta, ciphertext y etiqueta GCM, sin revelar la clave AES real de sesión. También permite inspeccionar el sobre JSON recibido y simular la interceptación con otra identidad registrada. La simulación intenta desenvolver la clave de sesión con la clave privada del usuario elegido; para una identidad distinta del destinatario, RSA-OAEP debe fallar.

| Módulo | Algoritmo y parámetros | Función |
|---|---|---|
| Hash | SHA-256, salida de 256 bits | Huella de integridad y demostración de efecto avalancha. |
| Simétrico | AES-256-GCM, nonce aleatorio de 96 bits | Confidencialidad y autenticación del contenido/campos AAD. |
| Asimétrico | RSA de 3072 bits, OAEP con SHA-256 | Protege solamente la clave de sesión para el destinatario. |
| Firma | RSA-PSS, SHA-256, MGF1-SHA-256 | Vincula la firma al contenido y a la clave privada del emisor. |
| Certificados | X.509 v3 firmado con RSA y SHA-256 | Asocia identidad y clave pública bajo confianza de la CA local. |

RSA se usa para transportar la clave de sesión, no el mensaje: el cifrado RSA admite entradas pequeñas y resulta menos eficiente para contenidos grandes. AES-GCM maneja el contenido de forma eficiente y detecta alteraciones. Una nueva clave y un nonce aleatorio se generan por mensaje; reutilizar un nonce con la misma clave GCM puede revelar relaciones entre textos y debilitar gravemente la autenticación.

En la demostración de avalancha, `hash-demo` altera un bit del primer byte (o usa un byte cero si el texto está vacío) y compara los dos resultados SHA-256. El número de bits distintos varía por entrada y no tiene que ser exactamente la mitad en una muestra concreta. MD5 y SHA-1 tienen ataques de colisión prácticos conocidos y no deben elegirse para integridad en sistemas nuevos; se usa SHA-256.

## 2. Objetivos de seguridad

| Objetivo | Mecanismo en el programa | Alcance |
|---|---|---|
| Confidencialidad | AES-256-GCM y envoltura RSA-OAEP de la clave | Solo el titular de la clave privada del destinatario obtiene la clave de sesión. |
| Integridad | Etiqueta GCM, SHA-256 y firma sobre el mensaje | Una alteración del sobre o del mensaje se detecta/rechaza. |
| Autenticidad | Certificado de emisor encadenado a la CA y firma RSA-PSS | Confirma que el mensaje corresponde a la clave privada asociada a la identidad certificada. |
| No repudio | Firma digital verificable | Aporta evidencia criptográfica, pero no garantiza por sí sola no repudio legal. Este prototipo carece de sellado de tiempo confiable, custodia probatoria y gestión de identidad formal. |

## 3. Ataques que se previenen

1. **Manipulación del texto o del sobre:** AES-GCM autentica ciphertext y AAD; tras descifrar, la huella y firma también se comprueban. Si falla GCM, hash o firma, se rechaza el mensaje.
2. **Suplantación del emisor:** un atacante sin la clave privada de Ana no puede producir una firma válida. Además, la clave pública se toma de un certificado cuya firma se valida contra la CA de confianza, y se comprueba el nombre esperado.
3. **Sustitución de clave pública del destinatario:** al enviar, el certificado de Luis se valida contra la CA local, incluida firma y vigencia, antes de usar su clave RSA para envolver la clave de sesión.
4. **Reenvío a otro destinatario o cambio de identidad:** remitente, destinatario y versión se ligan como AAD. Cambiarlos invalida la autenticación GCM; el receptor también compara la identidad de destino.
5. **Certificados ajenos o vencidos:** se rechazan si el emisor no coincide con la CA, su firma no valida, su identidad difiere o está fuera de vigencia.

## 4. Reproducción y evidencias

Los comandos completos de instalación, inicialización de la CA, registro de usuarios, envío y recepción están en `README.md`. Las pruebas automatizadas en `tests/test_securemsg.py` cubren: mensaje íntegro aceptado, ciphertext alterado rechazado, firma inválida rechazada, certificado no emitido por la CA rechazado y certificado vencido rechazado. Se ejecutan con `python -m unittest discover -s tests -v`.

## 5. Limitaciones y pasos para producción

Esta aplicación es una práctica local, no un servicio listo para producción. Las claves privadas PEM no tienen cifrado de contraseña y su protección depende de permisos del sistema de archivos. La interfaz permite mostrarlas explícitamente para el taller; cualquier persona con acceso a esa vista puede suplantar al usuario. La CA y el almacén de confianza son locales; no hay revocación mediante CRL/OCSP, rotación, respaldo seguro, HSM, control de acceso multiusuario ni auditoría. El programa no ofrece forward secrecy: si más adelante se roba la clave RSA privada del destinatario, sobres antiguos pueden quedar expuestos. Tampoco hay protección contra repetición ni identificador de mensaje/ventana temporal. Los metadatos del sobre (remitente, destinatario, fecha, tamaño) son visibles. La firma demuestra control de una clave, pero la identidad legal y el no repudio requieren procesos externos confiables.

Para producción se necesitaría un modelo de amenazas y protocolo revisados, claves protegidas por KMS/HSM, autenticación y autorización de usuarios, certificados con revocación y cadena de confianza administrada, actualización/rotación de claves, protección contra replay, registro seguro, límites de tamaño y errores, y evaluación criptográfica independiente. La elección de algoritmos y tamaños también debe mantenerse alineada con las políticas aplicables.
