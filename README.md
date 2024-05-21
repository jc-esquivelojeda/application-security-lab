# Laboratorio de implementacion de seguridad en aplicaciones

## Escenario 1: pseudocodigo para sistema de autenticación

```
FUNCTION authenticateUser(username, password):
  QUERY database WITH username AND password
  IF found RETURN True
  ELSE RETURN False
```
## Analisis

En base a el pseudocodigo presentado se presentan las siguientes sugerencias:

- Al recibir la informacion esta se debe sanitizar antes de llevar a cabo el proceso de  autenticacion para evitar inyeccion de sql o bien el xss almacenado y/o xss reflejado
-  Se debe asegurar que del lado de bd se cuenta con un algoritmo de cifrado y hashing  aplicado al password esto con el fin de evitar que por algun motivo se pueda acceder de manera visible a dicha información
- Alternativamente se  debe proporcionar un factor de autenticacion multiple o bien un one time password ligado al inicio de sesion con el fin de confirmar que quien realiza la autenticacion es quien dice ser
- se debe validar el numero de intentos maximos permitidos para iniciar sesion, en caso de error bloquear el servicio despues de cierto numero de acciones
- Se debe loguear cualquier intento fallido de inicio de sesion
- Al generar logs de monitoreo hacia el endpoint de inicios de sesion se debe asegurar de censurar información critica para evitar que en un ataque se pueda escalar y accedan a los logs de aplicación
- Se debe implementar soluciones para bloqueo temporal de usuario debido a numero de intentos maximo sobrepasado
- Se deben proteger los endpoints criticos mediante firewals y captchas para evitar ataques de denegacion de servicio o mediante robots
- se puede realizar monitoreo activo mediante umbrales para detectar cuando un endpoint tiene peticiones fuera de lo regular

## Solución

```
FUNCTION authenticateUser(username, password, recaptcha_response):
  IF NOT VERIFY_RECAPTCHA(recaptcha_response):
    RETURN False
  username = sanitize(username)
  password = sanitize(password)
  hashed_password = HASH(password)

  query = PREPARE_STATEMENT("SELECT * FROM user WHERE username = ? and password= ?")
  query.SET_PARAMETER(1, username)
  query.SET_PARAMETER(2, hashed_password)
  found = EXECUTE_QUERY(query)

  max_retries = 3
  IF found
    RETURN True
  ELSE
    log_autentication_failure(username, password)
    IF retries > max_retries
      temporal_lock_user(username)
    RETURN False
```

## Escenario 2: Esquema de autenticación JWT

```
DEFINE FUNCTION generateJWT(userCredentials):
  IF validateCredentials(userCredentials):
    SET tokenExpiration = currentTime + 3600 // Token expires in one hour
    RETURN encrypt(userCredentials + tokenExpiration, secretKey)
  ELSE:
    RETURN error
```

## Analisis
- se debe sanitizar la informacion recibida en la autenticacion para evitar inyeccion sql o bien el xss almacenado y/o xss reflejado
- se debe extraer el secretkey del codigo y pasarlo como una variable de entorno que venga desde un secret manager para evitar exponer credenciales desde repositorios disponibles o vulnerados ya que permitiria generar tokens falsificados
- Se debe implementar el servicio de refresh token  con el fin de disminuir la ventana de tiempo en que se encuentran activos los tokens disminuyendo asi el tiempo de accion con el que contaria un atacante en caso de acceder a un token y en su lugar solicitar un nuevo token despues de cierto tiempo mediante un refresh token
- Se sugiere definir los roles o nivel de autorizacion con que cuenta el usuario en el jwt para contrastar contra el servicio o endpoint que se quiere acceder

## Solución

```
 FUNCTION generateJWT(userCredentials):
    sanitize(userCredentials)
    IF  validCredentials(userCredentials):
        privateKey = GET_ENV_VAR("PRIVATE_KEY") // se recupera de un secret manager para que no este visible en el repositorio
        access_tokenExpiration = now + 900 // duración 15 minutos
        refresh_tokenExpiration = now + 86400 // duración 1 dia
        
        access_payload = {
            'sub': userCredentials.username,
            'roles': userCredentials.roles,
            'iat': now(),
            'exp': access_tokenExpiration,
            'jti': generateRandomTokenId(),
            'type': 'ACCESS_TOKEN'
        }
        
        refresh_payload = {
            'sub': userCredentials.username,
            'exp': refresh_tokenExpiration,
            'jti': generateRandomTokenId(),
            'type': 'REFRESH_TOKEN'
        }

        access_token = encrypt(access_payload, privateKey)
        refresh_token = encrypt(refresh_payload, privateKey)

        RETURN access_token, refresh_token
    ELSE:
        RETURN error

 FUNCTION refreshToken(refresh_token):
    IF validateRefreshToken(refresh_token): // si es aun valido el refresh, genera un nuevo token
        RETURN generateJWT(getUserCredentialsFromToken(refresh_token))
    ELSE
        RETURN error        
```


## Escenario 3: Plan de comunicacion de datos segura

```
PLAN secureDataCommunication:
  IMPLEMENT SSL/TLS for all data in transit
  USE encrypted storage solutions for data at rest
  ENSURE all data exchanges comply with HTTPS protocols
```

## Analisis
- Al guardar las credenciales se deben almacenar de manera cifrada
- Se debe contar con  certificados firmados por una entidad reconocida para la comunicacion de extremo a extremo 
- Se debe asegurar que el canal por el que se envia las credenciales a validar este encriptado para evitar el robo de la información (https)
- se debe configurar el servidor destino con certificados ssl para el objetivo anterior con el fin de que la comunicacion entre cliente y servidor este encriptada
- Se puede habilitar un firewall a nivel de servicio para evitar la denegacion de servicios y recaptcha para  limitar el numero de intentos


## Solución
```
PLAN secureDataCommunication:
  IMPLEMENT strong SSL/TLS for all data in transit
  USE encrypted storage solutions for data at rest
  ENSURE all data exchanges comply  only with HTTPS protocols
  Validate certificates on request to prevent man in the middle attack
  Use a web application Firewall to avoid sql injection and xss
  Limit access to the server or use keys instead of passwords
  Remove default passwords in used applications to avoid attacker guessing the default user/password  
  Add HttpOnly to prevent client side scripts
  Enable secure flag to only enable sending cookies through https
  Enable same site policy to restrict cookies sent : Set-Cookie: SID=12345; Secure; HttpOnly; SameSite=Strict;
```
