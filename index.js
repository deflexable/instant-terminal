import express from 'express';
import cors from 'cors';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { one_hour, one_mb, one_minute, one_year } from './values.js';
import { BASE_URL, CORS_ORIGIN, PORT, TERMINAL_PASSCODE, TERMINAL_SHELL, useRequestIpAssigner } from './env.js';
import { Server } from "socket.io";
import { createServer } from 'http';
import { spawn as EmulateTerminal } from 'node-pty';
import './app/terminal-env.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app_dir = join(__dirname, 'app');
const LoginDDOS = {};
const rateLimiter = { maxCalls: 3, millis: one_minute * 10 };

const app = express();
app.disable("x-powered-by");

app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: '100mb' }));
app.use(useRequestIpAssigner);

// handle login here
app.use((req, res, next) => {
    if (req.url === '/robots.txt') {
        res.status(200).send(`User-agent: *\nDisallow: /`);
        return;
    }

    if (req.url === '/favicon.ico') {
        res.sendFile(`${app_dir}${req.url}`);
        return;
    }

    if (req.url === '/auth') {
        res.sendFile(`${app_dir}/auth.html`);
        return;
    }

    if (req.url === '/login') {
        const ipAddress = req.cip;

        const destroyDDOS = () => {
            clearTimeout(LoginDDOS[ipAddress]?.timer);
            if (LoginDDOS[ipAddress]) delete LoginDDOS[ipAddress];
        }

        if (LoginDDOS[ipAddress]) {
            if (++LoginDDOS[ipAddress].calls > rateLimiter.maxCalls) {
                res.sendStatus(429);
                return;
            }
        } else {
            LoginDDOS[ipAddress] = {
                calls: 1,
                timer: setTimeout(destroyDDOS, rateLimiter.millis)
            };
        }

        if (req.body?.password === TERMINAL_PASSCODE) {
            res.cookie('secure-key', TERMINAL_PASSCODE, {
                httpOnly: true,  // Prevent JavaScript access to the cookie
                secure: false,    // Send cookie only over HTTPS
                sameSite: true, // Ensure the cookie is only sent for requests to the same site
                maxAge: one_year
            }).setHeader('Access-Control-Allow-Credentials', 'true')
                .sendStatus(200);
            destroyDDOS();
        } else res.status(500).send('Incorrect passcode provided, please try again');
        return;
    }

    const { 'secure-key': secureKey } = extractCookies(req);

    if (secureKey !== TERMINAL_PASSCODE) {
        if (req.url === '/') {
            res.redirect('/auth');
        } else res.status(500).send('Authorized Access');
        return;
    }

    if (req.url.startsWith('/node_modules/')) {
        res.sendFile(join(__dirname, req.url));
        return;
    }
    next();
});

app.use(express.static(app_dir, {
    cacheControl: false,
    extensions: ['html']
}));

const server = createServer(app);
const io = new Server(server, {
    pingTimeout: 4000,
    pingInterval: 1700,
    cors: { origin: CORS_ORIGIN },
    maxHttpBufferSize: one_mb * 100
});

const makeTerminal = () =>
    EmulateTerminal(TERMINAL_SHELL, [], {
        name: 'xterm-256color',
        cols: globalThis.TERMINAL_COL,
        rows: globalThis.TERMINAL_ROW,
        cwd: process.env.HOME,
        env: process.env
    });

/**
 * @type {import('node-pty').IPty}
 */
let terminal;
let residueLines = '';
let terminalKillTimer;

io.on('connection', async socket => {
    const { 'secure-key': secureKey } = extractCookies(socket.handshake);

    if (secureKey !== TERMINAL_PASSCODE) {
        console.error('unauthorized socket connection handshake', socket.handshake);
        socket.disconnect();
        return;
    }

    clearTimeout(terminalKillTimer);

    if (!terminal) {
        terminal = makeTerminal();
        terminal.onData(line => {
            residueLines += line;
        });
        terminal.onExit((e) => {
            console.log('terminal onExit err:', e);
            terminal = undefined;
            residueLines = '';
        });
    }

    if (residueLines) socket.emit('mount_terminal', residueLines);

    const listener = terminal.onData(line => {
        socket.emit('write_client_terminal', line);
    });

    socket.on('write_server_terminal', data => {
        terminal.write(data);
    });

    socket.on('disconnect', () => {
        terminalKillTimer = setTimeout(() => {
            terminal.kill();
        }, one_hour);
        listener.dispose();
    });
});

server.listen(PORT, () => {
    console.log(`Terminal GUI listening at port ${PORT}, please visit ${BASE_URL}`);
});

// error handler
app.use((err, req, res, next) => {
    console.log('Terminal GUI error', err);
    const error = {
        errmsg: err.errmsg,
        name: err.name,
    };
    return res.status(500).send(error);
});

function extractCookies(req) {
    const { cookie } = req.headers;
    return Object.fromEntries(
        (cookie || '').split('; ').map(c => c.split('='))
    );
}