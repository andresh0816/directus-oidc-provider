import { defineEndpoint } from '@directus/extensions-sdk';
import { Provider } from 'oidc-provider';

export default defineEndpoint({
	id: "oauth",
	handler: (router, context) => {
		const { services, logger, getSchema, env } = context;
		const clients = JSON.parse(env['OAUTH_CLIENTS'] || '[]');
		const { UsersService, RolesService } = services;

		const oidc = new Provider(env['PUBLIC_URL'], {
			clients,
			features: {
				deviceFlow: { enabled: true },
				introspection: { enabled: true },
				revocation: { enabled: true },
			},

			findAccount: async (ctx, sub) => {
				const schema = await getSchema();
				const accountability = (ctx.request as any).accountability;
				const usersService = new UsersService({ schema, accountability });
				const rolesService = new RolesService({ schema, accountability });

				try {
					const user = await usersService.readOne(sub);

					if (!user) return undefined;

					const role = await rolesService.readOne(user.role);

					return {
						accountId: sub,
						claims() {
							return {
								sub : user.id,
								email: user.email,
								role: role.name,
								name: user.first_name + ' ' + user.last_name,
							}
						},
					}
				}
				catch (error) {
					logger.error('Error finding account:', error);
					return undefined;
				}
			},


		})

		router.use('/oauth', oidc.callback());
	}
})