# Taller de mensajería segura

Implementación didáctica en Python de los módulos de hash, cifrado simétrico, cifrado híbrido, firma digital y certificados X.509. No implementa algoritmos criptográficos desde cero: usa la biblioteca `cryptography`.

## Interfaz web con Docker

Requiere Docker con Docker Compose. Desde la raíz del repositorio:

```bash
docker compose up --build
```

Abre [http://localhost:8000](http://localhost:8000). La pantalla permite crear la CA, registrar usuarios, enviar mensajes y descifrarlos/verificarlos desde la bandeja. La sección **Laboratorio por módulos** deja ejecutar independientemente SHA-256 y avalancha, AES-GCM, cifrado híbrido AES/RSA y firma/alteración. También valida certificados y demuestra el rechazo de uno no confiable y uno vencido. El **Flujo integrado** envía y recibe un mensaje completo.

Después de enviar, **Cómo se generó este mensaje** muestra el hash, la firma, el nonce, la clave AES envuelta, ciphertext y etiqueta GCM. En la bandeja, **Ver sobre interceptable** presenta el JSON que viaja por el canal. Registra un tercer usuario (por ejemplo `eva`) y usa **Intentar abrir la clave de sesión** para mostrar que su clave privada no puede desenvolver la clave AES de un mensaje dirigido a Luis.

El hash y la firma mostrados en la traza son valores de demostración; el sobre JSON contiene el ciphertext y los metadatos públicos. En **Ver credenciales generadas** puedes inspeccionar las claves y el certificado de cada usuario; al hacerlo se muestra también la clave privada, que debe mantenerse secreta. La clave AES de sesión del flujo real nunca se muestra. Solo los ejercicios independientes revelan claves temporales para enseñar los algoritmos. Para detener el servicio, usa `Ctrl+C`; los certificados, claves y mensajes permanecen en el volumen `securemsg-data`.

Por defecto el puerto se publica solo en `127.0.0.1`. La interfaz es una demo local sin inicio de sesión; no expongas el puerto a una red pública.

## Requisitos y ejecución

Se requiere Python 3.10 o posterior.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Desde la raíz del repositorio, crea una CA local y registra dos usuarios:

```bash
python -m securemsg --pki pki init-ca
python -m securemsg --pki pki register ana
python -m securemsg --pki pki register luis
```

Envía un mensaje firmado y cifrado y recíbelo:

```bash
python -m securemsg --pki pki send --from ana --to luis \
  --message "Nos vemos a las 10" --out mensaje.json
python -m securemsg --pki pki receive --as luis --in mensaje.json --expect-sender ana
```

La recepción imprime el mensaje y el resultado de las verificaciones. Una modificación del sobre, una firma inválida, un certificado que no encadena a la CA o un certificado vencido provoca rechazo. `--expect-sender` permite además fijar la identidad que se espera recibir.

Para observar una huella SHA-256 y el efecto de cambiar un bit del primer byte:

```bash
python -m securemsg hash-demo --message "mensaje original"
```

Ejecuta los casos automatizados requeridos con:

```bash
python -m unittest discover -s tests -v
```

## Estructura

- `securemsg/hashing.py`: huella y demostración del efecto avalancha.
- `securemsg/crypto_utils.py`: serialización, SHA-256, generación RSA, RSA-OAEP y RSA-PSS.
- `securemsg/certificates.py`: creación de CA, emisión de certificados y validaciones.
- `securemsg/messaging.py`: envío y recepción del sobre híbrido.
- `securemsg/cli.py`: comandos de usuario.
- `securemsg/webapp.py` y `securemsg/static/index.html`: API y UI web con FastAPI.
- `Dockerfile` y `compose.yaml`: empaquetado y ejecución del servicio web.
- `tests/test_securemsg.py`: aceptación del mensaje íntegro y rechazo ante manipulación, firma inválida, certificado ajeno y certificado vencido.
- `INFORME.md`: explicación técnica, análisis de ataques y limitaciones.

El directorio `pki/` contiene las claves privadas y certificados generados en tiempo de ejecución, por lo que está excluido del control de versiones.
