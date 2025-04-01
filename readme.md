# AuthAPI

Contiene todas las líneas del snippet original, organizado en una estructura modular.

## Cómo Iniciar
1. Configura tu `.env` (o ajusta `config.js` con tus valores).
2. Instala dependencias: `npm install`.
3. Ejecuta: `npm start`.

## Rutas Principales
- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/login/2fa
- POST /api/auth/refresh-token
- GET  /api/auth/2fa/generate
- POST /api/auth/2fa/validate
- GET  /api/auth/logout
- GET  /api/users/current
- GET  /api/admin
- GET  /api/moderator


## Bases de datos

### POSTGRES

docker run -d \
  --name my-postgres \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=mydatabase \
  -p 5432:5432 \
  postgres

Esquema

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    "2faEnable" BOOLEAN DEFAULT false,
    "2faSecret" TEXT,
    identityVerificationStatus TEXT DEFAULT 'Not verified',
    created_at TIMESTAMP DEFAULT NOW()
  );

### Redis

docker run -d --name redis-server -p 6379:6379 redis  
