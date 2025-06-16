# Directus OIDC Provider Extension

Esta extensión convierte tu instancia de Directus en un proveedor OpenID Connect (OIDC), permitiendo que otras aplicaciones usen Directus para autenticación SSO.

## Características

- ✅ Proveedor OIDC completo basado en [node-oidc-provider](https://github.com/panva/node-oidc-provider)
- ✅ Integración nativa con usuarios y roles de Directus
- ✅ Soporte para múltiples clientes OAuth
- ✅ Claims personalizados basados en roles de Directus
- ✅ Configuración flexible mediante variables de entorno
- ✅ Logging integrado con Directus
- ✅ Health checks y endpoints de diagnóstico

## Instalación

1. **Clona o descarga la extensión:**
   ```bash
   git clone <repository-url>
   cd directus-oidc-provider
   ```

2. **Instala las dependencias:**
   ```bash
   npm install
   ```

3. **Configura las variables de entorno:**
   ```bash
   cp .env.example .env
   # Edita .env con tu configuración
   ```

4. **Compila la extensión:**
   ```bash
   npm run build
   ```

5. **Copia a Directus:**
   ```bash
   # Copia el directorio completo a tu carpeta de extensiones de Directus
   cp -r . /path/to/directus/extensions/endpoints/oidc-provider/
   ```

6. **Reinicia Directus**

## Configuración

### Variables de Entorno Requeridas

```bash
# URL pública de tu instancia de Directus
PUBLIC_URL=https://your-directus-instance.com

# Configuración de clientes OAuth (JSON array)
OAUTH_CLIENTS='[
  {
    "client_id": "my-app",
    "client_secret": "my-secret",
    "redirect_uris": ["https://my-app.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"]
  }
]'

# Claves para firmar cookies (separadas por comas)
OIDC_COOKIE_KEYS=key1,key2,key3
```

### Ejemplo de Cliente SPA

```json
{
  "client_id": "spa-client",
  "client_secret": "",
  "redirect_uris": ["https://spa.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

### Ejemplo de Cliente Confidencial

```json
{
  "client_id": "server-app",
  "client_secret": "super-secret",
  "redirect_uris": ["https://server-app.example.com/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

## Endpoints Disponibles

Una vez instalada, la extensión expone los siguientes endpoints:

### Endpoints OIDC Estándar

- `GET /oauth/.well-known/openid_configuration` - Configuración del proveedor OIDC
- `GET /oauth/auth` - Endpoint de autorización
- `POST /oauth/token` - Endpoint de tokens
- `GET /oauth/me` - Endpoint de UserInfo
- `GET /oauth/jwks` - JSON Web Key Set
- `POST /oauth/token/revocation` - Revocación de tokens
- `POST /oauth/token/introspection` - Introspección de tokens

### Endpoints de Interacción

- `GET /oauth/interaction/:uid` - Detalles de interacción
- `POST /oauth/interaction/:uid/login` - Procesar login
- `POST /oauth/interaction/:uid/confirm` - Procesar consentimiento

### Endpoints de Diagnóstico

- `GET /oauth/health` - Health check
- `GET /oauth/.well-known/openid_configuration` - Configuración del proveedor

## Flujo de Autenticación

1. **Autorización**: El cliente redirige al usuario a `/oauth/auth`
2. **Interacción**: Si es necesario, se redirige a `/oauth/interaction/:uid`
3. **Login**: El usuario se autentica (integrar con Directus Auth)
4. **Consentimiento**: El usuario autoriza los scopes solicitados
5. **Callback**: Se redirige al cliente con el código de autorización
6. **Token**: El cliente intercambia el código por tokens en `/oauth/token`

## Claims Disponibles

### Scopes Estándar

- `openid`: Incluye `sub`
- `profile`: Incluye `name`, `given_name`, `family_name`, `role`
- `email`: Incluye `email`, `email_verified`
- `offline_access`: Permite refresh tokens

### Claims Personalizados

- `role`: Nombre del rol del usuario en Directus
- `email_verified`: Siempre `true` para usuarios activos

## Integración con Clientes

### Configuración Básica para un Cliente

```javascript
// Ejemplo usando oidc-client-js
import { UserManager } from 'oidc-client';

const userManager = new UserManager({
  authority: 'https://your-directus-instance.com/oauth',
  client_id: 'your-client-id',
  redirect_uri: 'https://your-app.com/callback',
  response_type: 'code',
  scope: 'openid profile email',
  post_logout_redirect_uri: 'https://your-app.com/',
});
```

### Configuración para Next.js con NextAuth

```javascript
// pages/api/auth/[...nextauth].js
import NextAuth from 'next-auth'

export default NextAuth({
  providers: [
    {
      id: 'directus',
      name: 'Directus',
      type: 'oauth',
      wellKnown: 'https://your-directus-instance.com/oauth/.well-known/openid_configuration',
      clientId: process.env.DIRECTUS_CLIENT_ID,
      clientSecret: process.env.DIRECTUS_CLIENT_SECRET,
      checks: ['pkce', 'state'],
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
          role: profile.role,
        }
      },
    }
  ],
})
```

## Desarrollo

### Scripts Disponibles

```bash
npm run build      # Compilar la extensión
npm run dev        # Compilar en modo desarrollo con watch
```

### Estructura del Proyecto

```
├── src/
│   └── index.ts           # Código principal de la extensión
├── package.json           # Configuración del paquete
├── tsconfig.json         # Configuración de TypeScript
├── .env.example          # Ejemplo de variables de entorno
└── README.md             # Esta documentación
```

## Resolución de Problemas

### Error: "PUBLIC_URL environment variable is required"

Asegúrate de que `PUBLIC_URL` esté configurado en tu archivo `.env` o variables de entorno de Directus.

### Error: "Invalid OAUTH_CLIENTS configuration"

Verifica que `OAUTH_CLIENTS` sea un JSON válido y contenga un array de objetos de cliente.

### Los tokens no se generan correctamente

1. Verifica que `OIDC_COOKIE_KEYS` esté configurado
2. Asegúrate de que las URLs de redirect coincidan exactamente
3. Revisa los logs de Directus para errores específicos

### Health Check

Puedes verificar que la extensión funcione correctamente visitando:
```
https://your-directus-instance.com/oauth/health
```

## Contribución

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crea un Pull Request

## Licencia

MIT License

## Referencias

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [node-oidc-provider](https://github.com/panva/node-oidc-provider)
- [Directus Extensions](https://docs.directus.io/extensions/)
