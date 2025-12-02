
export function initE2E(nacl) {
    /**
     * @type {import('tweetnacl-functional')}
     */
    const { box, randomBytes } = nacl;

    const pair = box.keyPair();

    return {
        pair,
        encrypt: (data, partyPubKey) => {
            const nonce = randomBytes(box.nonceLength);
            return {
                ugly: uint8ToBase64(box(utf16ToUint8(data), nonce, partyPubKey, pair.secretKey)),
                nonce: uint8ToBase64(nonce)
            };
        },
        decrypt: (data, partyPubKey) => {
            const { ugly, nonce } = data;
            return uint8ToUtf16(box.open(base64ToUint8(ugly), base64ToUint8(nonce), partyPubKey, pair.secretKey));
        }
    };
};

function utf16ToUint8(str) {
    const len = str.length;
    const bytes = new Uint8Array(len * 2);
    for (let i = 0; i < len; i++) {
        const code = str.charCodeAt(i);
        bytes[i * 2] = code & 0xff;         // low byte
        bytes[i * 2 + 1] = code >> 8;       // high byte
    }
    return bytes;
}

function uint8ToUtf16(bytes) {
    const len = bytes.length / 2;
    let str = '';
    for (let i = 0; i < len; i++) {
        const low = bytes[i * 2];
        const high = bytes[i * 2 + 1];
        const code = (high << 8) | low;
        str += String.fromCharCode(code);
    }
    return str;
}

export const uint8ToBase64 = (uint8) => {
    if (typeof Buffer === 'undefined') {
        let binary = "";
        uint8.forEach(b => binary += String.fromCharCode(b));
        return btoa(binary);
    }

    return Buffer.from(uint8).toString('base64');
}

export const base64ToUint8 = (base64) => {
    if (typeof Buffer === 'undefined') {
        const binary = atob(base64);
        const uint8 = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            uint8[i] = binary.charCodeAt(i);
        }
        return uint8;
    }
    return new Uint8Array(Buffer.from(base64, 'base64'));
}

if (typeof self !== 'undefined') {
    self.initE2E = initE2E;
    self.uint8ToBase64 = uint8ToBase64;
    self.base64ToUint8 = base64ToUint8;
}