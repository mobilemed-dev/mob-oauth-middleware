const OAuthMiddleware = require('./middleware');

module.exports = class OAuthMiddlewareSingleton {
    static createInstance(config) {
        if (!OAuthMiddlewareSingleton.instance) {
            OAuthMiddlewareSingleton.instance = new OAuthMiddleware(config);
        }
    }

    static getInstance() {
        if (!OAuthMiddlewareSingleton.instance) {
            throw new Error('OAuth Middleware is not initialized. Please, call createInstance method first.');
        }
        return OAuthMiddlewareSingleton.instance;
    }
}