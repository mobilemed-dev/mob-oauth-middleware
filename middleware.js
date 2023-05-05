const HttpResponse = require('mob-http-response');
const {default: TokenValidator} = require('mob-oauth2-jwt-validator');

module.exports = class OAuthMiddleware {
    constructor({ serverUrl, realm, clientId, clientSecret }) {
        this.oauthConfig = { serverUrl, realm, clientId, clientSecret };
    }

    protect(...args) {
        return async (req, res, next) => {
            if (!args || args.length === 0 || !args[0] || args[0].length === 0) {
                next();
                return;
            }

            if (!req.headers.authorization) {
                return HttpResponse.unauthorizedError(res);
            }

            const token = req.headers.authorization.split(' ')[1];
            const response = await this._introspectToken(token);
            if (response.status === 200) {
                const isActive =
                    response.data &&
                    response.data['cognito:groups'] &&
                    Array.isArray(response.data['cognito:groups']) &&
                    response.data['cognito:groups'].length > 0;

                if (!isActive) {
                    return HttpResponse.unauthorizedError(res);
                }

                const hasRole = args[0].some(a => response.data['cognito:groups'].includes(a));

                if (hasRole) {
                    next();
                } else {
                    return HttpResponse.forbiddenError(res);
                }
            } else {
                return res.status(response.status).json({ message: 'OAuth validation error', details: response.data });
            }
        }
    }

    async _introspectToken(token) {
        try {
            await TokenValidator.loadConfiguration({ oAuth2Issuer: this.oauthConfig.serverUrl })

            const isValid = TokenValidator.validate(token);

            if(!isValid) {
                return {
                    status: 401,
                    data: {
                        message: 'Invalid token'
                    }
                }
            }

            const data = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
            
            return {
                status: 200,
                data
            };
        } catch (error) {
            if (error.response) {
                return error.response;
            } else {
                throw error;
            }
        }
    }
}