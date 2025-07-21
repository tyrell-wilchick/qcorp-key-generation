#!/usr/bin/env node

const crypto = require('crypto');
const forge = require('node-forge');
const { mnemonicToSeed } = require('bip39');
const { random } = require('node-forge');

/**
 * Generate a TOTP secret based on a seed.
 * @param {string} user_id - The user id to generate the TOTP secret from.
 * @param {string} version - The version of the TOTP secret (starts with a and is incremented by 1 letter each time the secret is rotated.)
 * @returns {string} - The generated TOTP secret.
 */
function generateTOTPSecret(user_id = '0', version = 'a') {
    const seed = `${user_id}${version}`;
    console.log(`Seed: ${seed}`);
    const hash = crypto.createHash('sha256').update(seed).digest('hex');
    const secretBytes = crypto.createHmac('sha256', hash).update(seed).digest();
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    let base32Secret = '';
    let bits = 0;
    let buffer = 0;
    
    for (let i = 0; i < secretBytes.length; i++) {
        buffer = (buffer << 8) | secretBytes[i];
        bits += 8;
        
        while (bits >= 5) {
            base32Secret += base32Chars[(buffer >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        buffer <<= (5 - bits);
        base32Secret += base32Chars[buffer & 31];
    }
    
    return base32Secret.substring(0, 32);
}

/**
 * Generate an RSA signing key for JWT tokens based on "randomized" timestamp or supplied seed.
 * @param {string} rsa_seed - The seed used to generate an RSA keypair (optional). Defaults to a "randomized" timestamp.
 * @returns {Object} - Object containing private and public keys.
 */
async function generateRSAKey(rsa_seed) {
    const timestamp = Date.now();
    const timestampSeed = rsa_seed || `${timestamp + Math.floor(Math.random() * 1000)}`;
    const seed = (await mnemonicToSeed(timestampSeed)).toString('hex')

    const prng = random.createInstance();
    prng.seedFileSync = () => seed
    
    const rsa = forge.pki.rsa;
    const keypair = rsa.generateKeyPair({
        bits: 2048,
        e: 0x10001,
        prng: prng
    });
    
    return {
        privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
        publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
        timestamp: timestamp,
        seed: timestampSeed
    };
}

function showUsage() {
    console.log(`
QCORP Key Generation Tool

Usage:
  node keygen.js totp <user_id> <version> - Generate TOTP secret based on user_id and version (optional)
  node keygen.js rsa <seed> - Generate RSA signing key based on seed (optional)

Examples:
  node keygen.js totp 1000 a
  node keygen.js rsa 1234567890

Options:
  --help, -h
`);
}

async function main() {
    const args = process.argv.slice(2);
    
    if (args.includes('--help') || args.includes('-h') || args.length === 0) {
        showUsage();
        return;
    }

    if (args[0] === 'totp') {
        var user_id = args[1] || undefined;
        var version = args[2] || undefined;
    }

    if (args[0] === 'rsa' && args.length > 1) {
        var rsa_seed = args[1] || undefined;
    }
    
    try {
        switch (args[0]) {
            case 'totp':
                const totpSecret = generateTOTPSecret(user_id, version);
                console.log(`Generated TOTP Secret: ${totpSecret}`);
                break;
                
            case 'rsa':
                const rsaKeys = await generateRSAKey(rsa_seed);
                console.log('Generated RSA Keys:\n');
                console.log(rsaKeys.privateKey);
                console.log(rsaKeys.publicKey);
                if (rsaKeys.timestamp) {
                    console.log(`Timestamp: ${rsaKeys.timestamp}`);
                }
                console.log(`Seed: ${rsaKeys.seed}`);
                break;
            default:
                console.error(`Error: Unknown command.`);
                showUsage();
                process.exit(1);
        }
    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = {
    generateTOTPSecret,
    generateRSAKey
}; 
