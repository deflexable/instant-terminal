
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
    const buffer = new ArrayBuffer(str.length * 2); // 2 bytes per char
    const view = new Uint16Array(buffer);
    for (let i = 0; i < str.length; i++) {
        view[i] = str.charCodeAt(i);
    }
    return new Uint8Array(buffer);
}

function uint8ToUtf16(bytes) {
    const view = new Uint16Array(bytes.buffer);
    let str = '';
    for (let i = 0; i < view.length; i++) {
        str += String.fromCharCode(view[i]);
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