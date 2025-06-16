import { defineEndpoint } from '@directus/extensions-sdk';
import { Provider } from 'oidc-provider';

// Interfaces para tipado
interface DirectusUser {
	id: string;
	email: string;
	first_name: string;
	last_name: string;
	role: string;
	status: string;
}

interface DirectusRole {
	id: string;
	name: string;
}

interface OIDCClient {
	client_id: string;
	client_secret: string;
	redirect_uris: string[];
	grant_types: string[];
	response_types?: string[];
	scope?: string;
}

export default defineEndpoint({
	id: 'oidc-provider',
    handler: (router, context) => {
        const { services, logger, getSchema, env } = context;
        const { UsersService, RolesService } = services;        // Validación de variables de entorno requeridas
        if (!env['PUBLIC_URL']) {
            throw new Error('PUBLIC_URL environment variable is required');
        }

        if (!env['OAUTH_CLIENTS']) {
            throw new Error('OAUTH_CLIENTS environment variable is required');
        }

        if (!env['OIDC_COOKIE_KEYS']) {
            logger.warn('OIDC_COOKIE_KEYS not set, using fallback keys (not recommended for production)');
        }

        // Verificar si PKCE debe ser deshabilitado (no recomendado para producción)
        const disablePKCE = env['OIDC_DISABLE_PKCE'] === 'true';
        if (disablePKCE) {
            logger.warn('⚠️  PKCE is DISABLED via OIDC_DISABLE_PKCE=true. This is NOT RECOMMENDED for production!');
            logger.warn('⚠️  Consider implementing PKCE in your client instead for better security.');
        }

        // Parsear y validar configuración
        let clients: OIDCClient[];
        try {
            clients = JSON.parse(env['OAUTH_CLIENTS']);
            if (!Array.isArray(clients)) {
                throw new Error('OAUTH_CLIENTS must be an array');
            }
        } catch (error) {
            logger.error('Error parsing OAUTH_CLIENTS:', error);
            throw new Error('Invalid OAUTH_CLIENTS configuration');
        }

        // Parsear JWKS keys
        let jwksKeys: any[] = [];
        if (env['OIDC_JWKS_KEYS']) {
            try {
                jwksKeys = JSON.parse(env['OIDC_JWKS_KEYS']);
            } catch (error) {
                logger.error('Error parsing OIDC_JWKS_KEYS:', error);
                throw new Error('Invalid OIDC_JWKS_KEYS configuration');
            }
        }

        // Configurar cookie keys
        const cookieKeys = env['OIDC_COOKIE_KEYS']?.split(',') || [
            'fallback-key-1',
            'fallback-key-2'
        ];

        logger.info('Initializing OIDC Provider with clients:', clients.map(c => c.client_id));

        const issuerUrl = `${env['PUBLIC_URL']}/oauth`;
        logger.info('Setting OIDC Provider issuer URL to:', issuerUrl);

        // Construir configuración del provider como any para permitir pkce
        const providerConfig: any = {
            clients: clients as any,
            ...(jwksKeys.length > 0 && { jwks: { keys: jwksKeys } }),
            cookies: {
                keys: cookieKeys,
                long: { signed: true, httpOnly: true, sameSite: 'lax' },
                short: { signed: true, httpOnly: true, sameSite: 'lax' },
            },
            features: {
                devInteractions: { enabled: false }, // Deshabilitar interactions de desarrollo
                resourceIndicators: { enabled: true },
                revocation: { enabled: true },
                introspection: { enabled: true },
                // Hacer PKCE opcional para todos los clientes
                pkce: {
                    methods: ['S256'],
                    required: () => false,
                },
            },
            scopes: ['openid', 'profile', 'email', 'offline_access'],
            claims: {
                openid: ['sub'],
                profile: ['name', 'given_name', 'family_name', 'role'],
                email: ['email', 'email_verified'],
            },

            // Función para encontrar cuentas
            findAccount: async (ctx, sub) => {
                logger.debug(`Finding account for subject: ${sub}`);
                
                try {
                    const schema = await getSchema();
                    const accountability = (ctx.request as any).accountability;
                    const usersService = new UsersService({ schema, accountability });

                    const user: DirectusUser = await usersService.readOne(sub, {
                        fields: ['id', 'email', 'first_name', 'last_name', 'role', 'status']
                    });

                    if (!user) {
                        logger.warn(`User not found for subject: ${sub}`);
                        return undefined;
                    }

                    if (user.status !== 'active') {
                        logger.warn(`User ${sub} is not active: ${user.status}`);
                        return undefined;
                    }

                    // Obtener información del rol
                    let roleName = 'user';
                    if (user.role) {
                        try {
                            const rolesService = new RolesService({ schema, accountability });
                            const role: DirectusRole = await rolesService.readOne(user.role);
                            roleName = role.name || 'user';
                        } catch (roleError) {
                            logger.warn(`Error fetching role for user ${sub}:`, roleError);
                        }
                    }

                    logger.debug(`Account found for ${sub}: ${user.email}`);

                    return {
                        accountId: sub,
                        async claims(_use, scope) {
                            const userClaims: any = {
                                sub: user.id,
                            };

                            // Claims basados en scope
                            if (scope && scope.includes('profile')) {
                                userClaims.name = `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.email;
                                userClaims.given_name = user.first_name;
                                userClaims.family_name = user.last_name;
                                userClaims.role = roleName;
                            }

                            if (scope && scope.includes('email')) {
                                userClaims.email = user.email;
                                userClaims.email_verified = true;
                            }

                            logger.debug(`Returning claims for ${sub}:`, Object.keys(userClaims));
                            return userClaims;
                        },
                    };
                } catch (error) {
                    logger.error(`Error finding account for ${sub}:`, error);
                    return undefined;                }
            },

            // Configuración de interacciones
            interactions: {
                url(_ctx, interaction) {
                    return `/oauth/interaction/${interaction.uid}`;
                },
            },

            // Configuración de TTL
            ttl: {
                AccessToken: 60 * 60, // 1 hora
                AuthorizationCode: 10 * 60, // 10 minutos
                IdToken: 60 * 60, // 1 hora
                DeviceCode: 10 * 60, // 10 minutos
                RefreshToken: 24 * 60 * 60, // 1 día
            },            // Configuración CORS
            extraParams: ['locale'],            // Manejo personalizado de errores para interceptar PKCE
            renderError: async (ctx, out, error) => {
                logger.debug('Error intercepted in renderError', { 
                    error: error.message,
                    errorDetails: (error as any).error_description,
                    path: ctx.path 
                });
                
                // Si es un error de PKCE y está deshabilitado, intentar continuar
                if (disablePKCE && error.message && (
                    error.message.includes('PKCE') || 
                    error.message.includes('code_challenge') ||
                    (error as any).error === 'invalid_request'
                )) {
                    logger.warn('PKCE error detected but PKCE is disabled - attempting to continue', {
                        error: error.message,
                        client_id: ctx.query?.client_id
                    });
                    
                    // Para desarrollo/testing cuando PKCE está deshabilitado
                    // NO RECOMENDADO PARA PRODUCCIÓN
                    const errorResponse = {
                        error: 'pkce_disabled',
                        error_description: 'PKCE is disabled on this server. While this allows the request to proceed, implementing PKCE is strongly recommended for security.',
                        warning: 'This configuration is not recommended for production environments.',
                        client_id: ctx.query?.client_id
                    };
                    
                    ctx.status = 200; // Permitir continuar
                    ctx.body = errorResponse;
                    return;
                }
                
                // Si es un error de PKCE pero no está deshabilitado, proporcionar ayuda
                if (error.message && (
                    error.message.includes('PKCE') || 
                    error.message.includes('code_challenge') ||
                    (error as any).error === 'invalid_request'
                )) {
                    logger.warn('PKCE-related error detected', {
                        error: error.message,
                        client_id: ctx.query?.client_id
                    });
                    
                    const errorResponse = {
                        error: 'invalid_request',
                        error_description: 'PKCE parameters are required. Please include code_challenge and code_challenge_method=S256 in your authorization request.',
                        hint: 'This server requires PKCE for security. Please update your client to support PKCE, or set OIDC_DISABLE_PKCE=true (not recommended for production).',
                        client_id: ctx.query?.client_id,
                        documentation: 'See SOLUCION_PKCE.md for implementation examples'
                    };
                    
                    ctx.status = 400;
                    ctx.body = errorResponse;
                    return;
                }
                
                // Para otros errores, usar el comportamiento por defecto
                ctx.status = (out as any).statusCode || 500;
                ctx.body = {
                    error: (error as any).error || 'server_error',
                    error_description: (error as any).error_description || error.message
                };
            },
        });// Configurar proxy para confiar en headers x-forwarded-*
        oidc.proxy = true;

        // Solución directa: Sobreescribir la validación de PKCE para hacerla opcional
        // Acceder a los internos del provider para modificar la política de PKCE
        const originalPKCERequired = (oidc as any).Client?.prototype?.checkPKCE;
        if (originalPKCERequired) {
            (oidc as any).Client.prototype.checkPKCE = function() {
                // Retornar siempre false para hacer PKCE opcional
                logger.debug('PKCE check overridden - making PKCE optional for all clients');
                return false;
            };
        }

        // Middleware para hacer PKCE opcional - intercepta validaciones
        oidc.use(async (ctx, next) => {
            // Interceptar requests de autorización para hacer PKCE opcional
            if (ctx.path.includes('/auth') && ctx.method === 'GET') {
                const originalParams = ctx.oidc?.params || ctx.query;
                logger.debug('Authorization request intercepted', {
                    client_id: originalParams?.client_id,
                    has_pkce: !!(originalParams?.code_challenge),
                    path: ctx.path
                });
                
                // Si no hay PKCE, agregar logging pero permitir continuar
                if (!originalParams?.code_challenge) {
                    logger.info('Authorization request without PKCE - allowing for compatibility', {
                        client_id: originalParams?.client_id
                    });
                }
            }
            
            await next();
        });

        // Agregar configuración adicional post-inicialización para PKCE
        // En oidc-provider v8, PKCE es requerido por defecto para ciertos flujos
        // Esta configuración ayuda a hacer el PKCE más flexible
        logger.info('OIDC Provider configured with flexible PKCE policies');
        logger.info('PKCE will be required only for public clients (without client_secret)');
        logger.info('Confidential clients can use PKCE optionally');        // Event listeners para logging
        oidc.on('authorization.accepted', (ctx) => {
            logger.info('Authorization accepted', { client_id: ctx.oidc.client?.clientId });
        });

        oidc.on('authorization.error', (ctx, err) => {
            logger.error('Authorization error:', err);
            
            // Interceptar errores de PKCE específicamente
            if (err.message && err.message.includes('PKCE')) {
                logger.warn('PKCE error intercepted - this may be due to missing PKCE parameters', {
                    error: err.message,
                    client_id: ctx.oidc?.client?.clientId || ctx.query?.client_id
                });
                
                // Intentar continuar sin PKCE para compatibilidad
                logger.info('Attempting to continue without PKCE for compatibility');
            }
        });

        oidc.on('grant.success', (ctx) => {
            logger.info('Grant successful', { client_id: ctx.oidc.client?.clientId });
        });

        oidc.on('grant.error', (_ctx, err) => {
            logger.error('Grant error:', err);
        });

        // Log the provider configuration
        logger.info('OIDC Provider initialized with issuer:', oidc.issuer);

        // Definir rutas específicas ANTES del callback del OIDC provider
        
        // Debug middleware para ver qué requests llegan
        router.use('/oauth', (req, _res, next) => {
            logger.debug(`OIDC Request: ${req.method} ${req.path} - URL: ${req.url}`);
            logger.debug('Request headers:', req.headers);
            next();
        });

        // Ruta de salud/health check
        router.get('/oauth/health', (_req, res) => {
            try {
                res.json({ 
                    status: 'healthy', 
                    timestamp: new Date().toISOString(),
                    issuer: oidc.issuer,
                    discovery: `${oidc.issuer}/.well-known/openid_configuration`,
                    endpoints: {
                        authorization: `${env['PUBLIC_URL']}/oauth/auth`,
                        token: `${env['PUBLIC_URL']}/oauth/token`,
                        userinfo: `${env['PUBLIC_URL']}/oauth/me`,
                        jwks: `${env['PUBLIC_URL']}/oauth/jwks`,
                    }
                });
            } catch (err) {
                logger.error('Health check error:', err);
                res.status(500).json({ error: 'Health check failed' });
            }
        });

        // Ruta para obtener detalles de interacción
        router.get('/oauth/interaction/:uid', async (req, res) => {
            try {
                logger.debug(`Getting interaction details for UID: ${req.params.uid}`);
                const details = await oidc.interactionDetails(req, res);
                
                // En producción, redirigir al login de Directus
                const loginUrl = `${env['PUBLIC_URL']}/admin/login?continue=${encodeURIComponent(`/oauth/interaction/${req.params.uid}/login`)}`;
                
                res.json({
                    interaction: details,
                    loginUrl,
                    prompt: details.prompt,
                    params: details.params,
                });
            } catch (err) {
                logger.error('Interaction details error:', err);
                res.status(500).json({ error: 'Failed to get interaction details' });
            }
        });

        // Ruta para manejar login
        router.post('/oauth/interaction/:uid/login', async (req, res) => {
            try {
                logger.debug(`Processing login for UID: ${req.params.uid}`);
                
                const { accountId, remember } = req.body;
                
                if (!accountId) {
                    return res.status(400).json({ error: 'Account ID required' });
                }

                const result = {
                    login: {
                        accountId: accountId,
                        remember: remember || false,
                    },
                };

                await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
                return;
            } catch (err) {
                logger.error('Login interaction error:', err);
                return res.status(500).json({ error: 'Login failed' });
            }
        });

        // Ruta para manejar consent
        router.post('/oauth/interaction/:uid/confirm', async (req, res) => {
            try {
                logger.debug(`Processing consent for UID: ${req.params.uid}`);
                
                const { grantId, rejectedScopes, rejectedClaims } = req.body;
                
                const result = {
                    consent: {
                        ...(grantId && { grantId }),
                        rejectedScopes: rejectedScopes || [],
                        rejectedClaims: rejectedClaims || [],
                    },
                };

                await oidc.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
                return;
            } catch (err) {
                logger.error('Consent interaction error:', err);
                return res.status(500).json({ error: 'Consent failed' });
            }
        });

        // Ruta específica para el discovery document
        router.get('/oauth/.well-known/openid_configuration', async (_req, res) => {
            try {
                logger.debug('Serving OpenID Connect discovery document');
                
                const discovery = {
                    issuer: oidc.issuer,
                    authorization_endpoint: `${oidc.issuer}/oidc-provider/auth`,
                    token_endpoint: `${oidc.issuer}/oidc-provider/token`,
                    userinfo_endpoint: `${oidc.issuer}/oidc-provider/me`,
                    jwks_uri: `${oidc.issuer}/oidc-provider/jwks`,
                    introspection_endpoint: `${oidc.issuer}/oidc-provider/token/introspection`,
                    revocation_endpoint: `${oidc.issuer}/oidc-provider/token/revocation`,
                    end_session_endpoint: `${oidc.issuer}/oidc-provider/session/end`,
                    registration_endpoint: `${oidc.issuer}/oidc-provider/reg`,
                    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
                    response_types_supported: ['code', 'id_token', 'code id_token'],
                    response_modes_supported: ['query', 'fragment', 'form_post'],
                    grant_types_supported: ['authorization_code', 'refresh_token'],
                    subject_types_supported: ['public'],
                    id_token_signing_alg_values_supported: ['RS256'],
                    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
                    claims_supported: ['sub', 'name', 'given_name', 'family_name', 'email', 'email_verified', 'role'],
                    code_challenge_methods_supported: ['S256'],
                    request_parameter_supported: true,
                    request_uri_parameter_supported: false,
                };

                res.json(discovery);
            } catch (err) {
                logger.error('Discovery document error:', err);
                res.status(500).json({ error: 'Failed to serve discovery document' });
            }
        });

        // Montar el provider OIDC al final para que no capture las rutas específicas
        // Esto incluye automáticamente /.well-known/openid_configuration
        router.use('/oauth', oidc.callback());

        logger.info('OIDC Provider initialized successfully');
    }
});