const axios = require('axios');
const qs = require('qs');
const HttpResponse = require('mob-http-response');

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
                    response.data.active === true;

                if (!isActive) {
                    return HttpResponse.unauthorizedError(res);
                }

                const hasRole = args[0].some(a => response.data.resource_access[this.oauthConfig.clientId].roles.includes(a));

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
            const url = `${this.oauthConfig.serverUrl}/realms/${this.oauthConfig.realm}/protocol/openid-connect/token/introspect`;
            const headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            const data = {
                token: token,
                client_id: this.oauthConfig.clientId,
                client_secret: this.oauthConfig.clientSecret
            }
            const response = await axios.post(url, qs.stringify(data), { headers })
            return response;
        } catch (error) {
            if (error.response) {
                return error.response;
            } else {
                throw error;
            }
        }
    }
}