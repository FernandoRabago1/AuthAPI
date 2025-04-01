
---

# **API: Secure Authentication & Authorization**

Este proyecto provee un sistema de **login con 2FA**, **tokens JWT** (access/refresh) y **revocación de tokens** usando **Redis**. 

## **Tabla de Contenido**

1. [Arquitectura y Flujo General](#arquitectura-y-flujo-general)  
2. [Configuraciones de Seguridad](#configuraciones-de-seguridad)  
3. [Endpoints Principales](#endpoints-principales)  
   - [Registro](#1-registro-post-apiauthregister)  
   - [Login](#2-login-post-apiauthlogin)  
   - [Login con 2FA](#3-login-2fa-post-apiauthlogin2fa)  
   - [Refresh Token](#4-refresh-token-post-apiauthrefresh-token)  
   - [Generar 2FA QR](#5-generar-2fa-get-apiauth2fagenerate)  
   - [Validar 2FA](#6-validar-2fa-post-apiauth2favalidate)  
   - [Logout](#7-logout-get-apiauthlogout)  
4. [Rutas de Usuario](#rutas-de-usuario)  
5. [Formato de Respuestas y Errores](#formato-de-respuestas-y-errores)  
6. [Manejo de Cookies y Tokens](#manejo-de-cookies-y-tokens)  
7. [Glosario de Términos](#glosario-de-términos)

---

## **Arquitectura y Flujo General**

1. **Autenticación** basada en **JWT**:
   - **Access Token** de vida corta (p.ej., 15m).
   - **Refresh Token** de vida larga (p.ej., 7d).
2. **Ambos tokens** se envían al cliente en **cookies HTTPOnly**:
   - `accessToken`: para acceder a rutas protegidas.
   - `refreshToken`: para renovar el access token cuando expira.
3. **Revocación** de tokens con **Redis**:
   - Al hacer logout, el `accessToken` y el `refreshToken` se invalidan en Redis.
   - El middleware verifica en Redis si el token fue revocado en cada petición.
4. **2FA** (Two-Factor Authentication) usando **OTP** (via otplib):
   - El usuario puede habilitar 2FA; en tal caso, primero hace login, luego genera un `tempToken` y necesita llamar a `/login/2fa` con su TOTP.
5. **Cookies** + **CORS**:
   - El front-end envía credenciales con `{ credentials: 'include' }`.
   - El servidor habilita CORS con `origin: <dominio>` y `credentials: true`.

---

## **Configuraciones de Seguridad**

- **Cookies HTTPOnly**: impiden que JavaScript en el navegador lea el token, mitigando ataques XSS.  
- **Short-living Access Token**: reduce ventana de compromiso si se roba el token.  
- **Refresh Token Rotación**: cada uso elimina el refresh token anterior y crea uno nuevo.  
- **Redis** para invalidar tokens antes de su expiración.  
- **2FA** (opcional) para añadir una capa adicional de seguridad al login.

---

## **Endpoints Principales**

A continuación se describen los **endpoints** del sistema de autenticación. Todos los endpoints devuelven **JSON** a menos que se indique lo contrario.

### **1) Registro** (`POST /api/auth/register`)

- **Descripción**: Crea un nuevo usuario en la base de datos.
- **Body** (JSON):
  ```json
  {
    "name": "John Doe",
    "email": "john@example.com",
    "password": "123456",
    "role": "admin"    // opcional, por defecto "member"
  }
  ```
- **Respuesta** (ejemplo 201 Created):
  ```json
  {
    "message": "User registered successfully",
    "id": "someUserId"
  }
  ```
- **Errores**:
  - `409 Conflict`: Email ya existe.
  - `422 Unprocessable Entity`: Faltan campos requeridos.

---

### **2) Login** (`POST /api/auth/login`)

- **Descripción**: Autentica con email y password.  
  - Si el usuario tiene 2FA habilitado, se responde con un `tempToken` y se omite la entrega de tokens definitivos.
  - Si no tiene 2FA, se setean cookies con `accessToken` y `refreshToken`.
- **Body** (JSON):
  ```json
  {
    "email": "john@example.com",
    "password": "123456"
  }
  ```
- **Respuestas**:
  - **2FA Habilitado**:  
    ```json
    {
      "tempToken": "<UUID>",
      "expiresInSeconds": 180
    }
    ```
    Luego se debe llamar a `/api/auth/login/2fa`.
  - **2FA Deshabilitado**:  
    - Cookies HTTPOnly: `accessToken` (15m), `refreshToken` (7d).  
    - Body JSON (ejemplo):
      ```json
      {
        "id": "someUserId",
        "name": "John Doe",
        "email": "john@example.com"
      }
      ```
- **Errores**:
  - `401 Unauthorized`: Credenciales inválidas.

---

### **3) Login 2FA** (`POST /api/auth/login/2fa`)

- **Descripción**: Intercambia el `tempToken` y un TOTP para obtener los tokens definitivos.
- **Body** (JSON):
  ```json
  {
    "tempToken": "temp_token",
    "totp": "123456"
  }
  ```
- **Respuesta**: 
  - Setea cookies `accessToken` y `refreshToken` en HTTPOnly.  
  - Body JSON:
    ```json
    {
      "id": "someUserId",
      "name": "John Doe",
      "email": "john@example.com"
    }
    ```
- **Errores**:
  - `401 Unauthorized`: TOTP incorrecto o `tempToken` inválido/expirado.

---

### **4) Refresh Token** (`POST /api/auth/refresh-token`)

- **Descripción**: Renueva el `accessToken` usando el `refreshToken` que está en la cookie.
- **Flujo**: 
  1. Lee la cookie `refreshToken`.
  2. Verifica que no esté revocado ni expirado.
  3. Emite un `newAccessToken` y un `newRefreshToken`.
  4. Setea ambos en cookies, invalidando el refresh token anterior.
- **Respuesta**:
  ```json
  {
    "message": "Access token refreshed successfully"
  }
  ```
- **Errores**:
  - `401 Unauthorized`: refresh token inválido o no encontrado.

---

### **5) Generar 2FA** (`GET /api/auth/2fa/generate`) 

- **Requiere** `accessToken`.
- **Respuesta**: Devuelve un **código QR** (mime-type `image/png`) que el usuario puede escanear con Google Authenticator u otra app TOTP.
- **Flujo**:
  1. Se genera un secreto TOTP con `otplib`.
  2. Se retorna un **PNG** descargable.

---

### **6) Validar 2FA** (`POST /api/auth/2fa/validate`)

- **Requiere** `accessToken` (usuario ya logueado).
- **Body** (JSON):
  ```json
  {
    "totp": "123456"
  }
  ```
- **Descripción**: Habilita 2FA en la cuenta verificando que el TOTP es correcto.
- **Respuesta**:
  ```json
  {
    "message": "TOTP validated successfully"
  }
  ```

---

### **7) Logout** (`GET /api/auth/logout`)

- **Requiere** `accessToken`.
- **Acciones**:
  1. Invalida (revoca) el `accessToken` y el `refreshToken` actual en Redis (o base).
  2. Limpia cookies con `res.clearCookie`.
- **Respuesta**: 
  - Código `204 No Content` si todo ok.
  - El cliente queda desautenticado.

---

## **Rutas de Usuario**

Además de las rutas `/api/auth/*`, tu aplicación puede tener otras rutas, por ejemplo:

- **`GET /api/users/current`**  
  - Retorna info del usuario actual, usando `ensureAuthenticated`.  
- **`GET /api/users/admin`**  
  - Requiere `ensureAuthenticated` + `authorize(['admin'])`.  
- **`GET /api/users/moderator`**  
  - Requiere `admin` o `moderator`.

Estas rutas deben mandar la **cookie** `accessToken` (automáticamente gestionada por el navegador si está en el mismo dominio, o `{ credentials: 'include' }` en un front-end cross-site).

---

## **Formato de Respuestas y Errores**

- **Respuestas exitosas**: devuelven un JSON con `message` y/o campos relevantes.  
- **Errores**: devuelven un JSON con `message` y un código HTTP 4xx o 5xx.  
  - `401 Unauthorized` para credenciales inválidas o token expirado.  
  - `403 Forbidden` para falta de rol/permiso.  
  - `409 Conflict` para registros duplicados.  
  - `422 Unprocessable Entity` para faltas de campos.

---

## **Manejo de Cookies y Tokens**

1. **El servidor** setea `accessToken` (vida corta) y `refreshToken` (vida larga) en cookies HTTPOnly.  
2. **El front-end** no puede leerlos con JavaScript (por `httpOnly: true`), pero los envía en cada request con `{ credentials: 'include' }`.  
3. **Al expirar** el `accessToken`, se llama `/api/auth/refresh-token`, que genera uno nuevo y actualiza la cookie `accessToken`.  
4. **Logout** elimina ambos tokens del cliente y los revoca en Redis, impidiendo su reutilización.

---

## **Glosario de Términos**

- **Access Token**: JWT de **vida corta** (p.ej. 15 minutos) usado para autorizar requests a rutas protegidas.  
- **Refresh Token**: JWT de **vida larga** (p.ej. 7 días) usado para obtener nuevos `accessTokens`.  
- **HTTPOnly Cookie**: Cookie no accesible por JavaScript, lo que mitiga ataques XSS.  
- **Redis**: Base de datos en memoria usada para invalidar tokens (lista negra).  
- **TOTP (2FA)**: “Time-Based One-Time Password” para verificar que el usuario tiene un dispositivo de autenticación adicional.  
- **NeDB**: Base de datos local que en esta implementación se usa para almacenar usuarios y, opcionalmente, otras colecciones.

---

## **Conclusión**

Esta API provee un **flujo robusto** de autenticación:

1. **Registro** y **login** con credenciales.  
2. **2FA opcional** para mayor seguridad.  
3. **Short-living access tokens** que se renuevan con un **refresh token**.  
4. **Revocación** de tokens en **Redis** para logout real.  
5. **Uso de cookies HTTPOnly** para proteger tokens frente a XSS.

Con estas pautas y endpoints, un equipo de ingenieros puede **integrar** tu API fácilmente, sea desde un front-end SPA, una app móvil, o un microservicio. ¡Listo!
