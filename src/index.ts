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
        const { UsersService, RolesService } = services;

        // Validación de variables de entorno requeridas
        if (!env['PUBLIC_URL']) {
            throw new Error('PUBLIC_URL environment variable is required');
        }

        if (!env['OAUTH_CLIENTS']) {
            throw new Error('OAUTH_CLIENTS environment variable is required');
        }

        if (!env['OIDC_COOKIE_KEYS']) {
            logger.warn('OIDC_COOKIE_KEYS not set, using fallback keys (not recommended for production)');
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

        const oidc = new Provider(issuerUrl, {
            clients: clients as any, // Type assertion para evitar problemas de tipado
            
            // Configuración de JWKS
            ...(jwksKeys.length > 0 && { jwks: { keys: jwksKeys } }),
            
            // Configuración de cookies
            cookies: {
                keys: cookieKeys,
                long: { 
                    signed: true, 
                    httpOnly: true,
                    sameSite: 'lax'
                },
                short: { 
                    signed: true, 
                    httpOnly: true,
                    sameSite: 'lax'
                },
            },

            // Características habilitadas
            features: {
                devInteractions: { enabled: false }, // Deshabilitar interactions de desarrollo
                resourceIndicators: { enabled: true },
                revocation: { enabled: true },
                introspection: { enabled: true },
            },

            // Scopes disponibles
            scopes: ['openid', 'profile', 'email', 'offline_access'],

            // Claims disponibles
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
                    return undefined;
                }
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
            },

            // Configuración CORS
            extraParams: ['locale'],
        });

        // Event listeners para logging
        oidc.on('authorization.accepted', (ctx) => {
            logger.info('Authorization accepted', { client_id: ctx.oidc.client?.clientId });
        });

        oidc.on('authorization.error', (_ctx, err) => {
            logger.error('Authorization error:', err);
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

        // Montar el provider OIDC al final para que no capture las rutas específicas
        // Esto incluye automáticamente /.well-known/openid_configuration
        router.use('/oauth', oidc.callback());

        logger.info('OIDC Provider initialized successfully');
    }
});