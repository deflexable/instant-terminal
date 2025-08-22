
export const {
    TERMINAL_PASSCODE = '12345',
    PORT = 7282,
    HOST_NAME = 'localhost',
    DOMAIN_SUFFIX = 'com',
    NODE_ENV = 'development',
    TERMINAL_SHELL = '/bin/bash'
} = process.env;

export const IS_DEV = NODE_ENV === 'development';

export const BASE_URL = IS_DEV ? `http://${HOST_NAME}:${PORT}` : `https://${HOST_NAME}.${DOMAIN_SUFFIX}`;

export const useRequestIpAssigner = (req, _, next) => {
    if (req.ip) {
        req.cip = req.ip;
    } else req.cip = req.headers?.['cf-connecting-ip'] || '';
    if (req.headers) req.headers.cip = req.cip;
    next();
};

export const CORS_ORIGIN = IS_DEV || new RegExp(`^https?:\/\/(?:[a-zA-Z0-9-]+\\.)*${HOST_NAME}\.${DOMAIN_SUFFIX}`);