# Configuración de PKCE para el OIDC Provider

## Problemas Resueltos

### 1. ✅ Warning de Proxy
**Error original**: `x-forwarded-proto header detected but not trusted, you must set proxy=true`

**Solución implementada**: Se agregó `oidc.proxy = true;` en el código para confiar en los headers `x-forwarded-*` cuando la aplicación está detrás de un proxy o reverse proxy.

### 2. ⚠️ Error de PKCE
**Error original**: `Authorization Server policy requires PKCE to be used for this request`

**Explicación**: Este error indica que el servidor OIDC está configurado para requerir PKCE (Proof Key for Code Exchange), pero el cliente no está enviando los parámetros necesarios.

## Soluciones para el Error de PKCE

### Opción 1: Configurar el Cliente para Usar PKCE (Recomendado)

El cliente que realiza la solicitud de autorización debe incluir los parámetros PKCE:

```javascript
// Generar code_verifier (43-128 caracteres)
const codeVerifier = generateRandomString(128);

// Generar code_challenge (SHA256 hash del code_verifier)
const codeChallenge = base64urlEncode(sha256(codeVerifier));

// URL de autorización con PKCE
const authUrl = `${OIDC_ISSUER}/auth?` +
  `response_type=code&` +
  `client_id=${CLIENT_ID}&` +
  `redirect_uri=${REDIRECT_URI}&` +
  `scope=openid profile email&` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256&` +
  `state=${state}`;
```

### Opción 2: Configurar los Clientes en Variables de Entorno

Asegúrate de que la configuración de clientes en `OAUTH_CLIENTS` sea correcta:

```json
[
  {
    "client_id": "tu_client_id",
    "client_secret": "tu_client_secret_opcional",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email"
  }
]
```

**Nota importante**: 
- **Clientes confidenciales** (con `client_secret`): PKCE es opcional
- **Clientes públicos** (sin `client_secret`): PKCE es requerido por seguridad

### Opción 3: Implementación con JavaScript

```javascript
// Función para generar code_verifier
function generateCodeVerifier() {
  const array = new Uint32Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}

// Función para generar code_challenge
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Uso
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Guarda el codeVerifier para usarlo en el intercambio de token
sessionStorage.setItem('code_verifier', codeVerifier);
```

## Configuraciones Implementadas en el Servidor

1. **`oidc.proxy = true`**: Permite confiar en headers de proxy
2. **`clientDefaults`**: Configuración por defecto para clientes que hace PKCE más flexible
3. **Logging mejorado**: Para debug de problemas relacionados con PKCE
4. **Discovery document**: Anuncia soporte para PKCE con método S256

## Verificación

Para verificar que PKCE está funcionando correctamente:

1. Revisa los logs del servidor para ver si se detecta PKCE:
   ```
   Authorization accepted { client_id: 'tu_client', pkce_used: true }
   ```

2. Verifica el discovery document en: `${PUBLIC_URL}/oauth/.well-known/openid_configuration`
   - Debe incluir: `"code_challenge_methods_supported": ["S256"]`

3. Para clientes confidenciales, PKCE es opcional pero recomendado
4. Para clientes públicos, PKCE es obligatorio por seguridad

## Ejemplo de Flujo Completo con PKCE

1. **Generar parámetros PKCE** en el cliente
2. **Redirigir a autorización** con `code_challenge`
3. **Usuario se autentica** y autoriza
4. **Recibir authorization code** en redirect_uri
5. **Intercambiar code por tokens** enviando `code_verifier`

```javascript
// Intercambio de token
const tokenResponse = await fetch(`${OIDC_ISSUER}/token`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code: authorizationCode,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier // El mismo que generaste antes
  })
});
```

## Troubleshooting

Si sigues teniendo problemas con PKCE:

1. Verifica que el `code_challenge_method` sea `S256`
2. Asegúrate de que el `code_verifier` tenga entre 43-128 caracteres
3. Confirma que el `code_challenge` sea un hash SHA256 base64url del `code_verifier`
4. Revisa los logs del servidor para más detalles sobre el error
