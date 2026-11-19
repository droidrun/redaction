/** Secret-shaped sample values: one or more per rule of the standard tier and some for the full tier. */
import { BASE62, chars, HEX, KEY_ALPHABET, mulberry32 } from './rng.ts';

const rng = mulberry32(0x5a3c1e);
const UUID_A = '3fa85f64-5717-4562-b3fc-2c963f66afa6';
const UUID_B = '9b2e1c7a-0d44-4e8b-a1f3-6c5d7e8f9a0b';

function segment(length: number): string {
    return chars(rng, KEY_ALPHABET, length);
}

export const FORMAT_SAMPLES: readonly string[] = [
    `eyJ${segment(20)}.${segment(24)}.${segment(30)}`,
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.' +
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c',
    `AIza${segment(35)}`,
    'AIzaSyA-1B2C3D4E5F6G7H8I9J0K1L2M3N4O5-',
    `xai-${chars(rng, `${BASE62}_`, 80)}`,
    `srt1.${UUID_A}.1731900000.${segment(43)}`,
    `srt2.${UUID_A}.${UUID_B}.agent.1731900000.${chars(rng, HEX, 64)}`,
    `srt2.${UUID_A}.${UUID_B}.worker.42.${chars(rng, HEX, 64)}`,
    `dr_sk_${segment(24)}`,
    `ghp_${chars(rng, BASE62, 36)}`,
    `gho_${chars(rng, BASE62, 40)}`,
    `github_pat_${chars(rng, `${BASE62}_`, 40)}`,
    'AKIAIOSFODNN7EXAMPLE',
    'ASIAY34FZKBOKMUTVV7A',
    `xoxb-${chars(rng, `${BASE62}-`, 30)}`,
    `sk_live_${chars(rng, BASE62, 24)}`,
    `rk_test_${chars(rng, BASE62, 24)}`,
    `sk-${chars(rng, `${BASE62}_-`, 48)}`,
    `sk-proj-${chars(rng, `${BASE62}_-`, 48)}`,
    `sk-ant-api03-${chars(rng, `${BASE62}_-`, 60)}`,
    `sk-svcacct-${chars(rng, `${BASE62}_-`, 40)}`,
    `sk-admin-${chars(rng, `${BASE62}_-`, 40)}`,
    'postgres://app:Zq9s3cretValue_x@db.example.test:5432/app',
    'https://user:p4ssW0rd!x@example.test/path',
    'Cookie: session=Zq9abcDEF123ghi; theme=dark',
    'Set-Cookie: sid=Zq9abcDEF123ghi; Path=/; HttpOnly',
    '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nabc+/=\n' +
        '-----END PRIVATE KEY-----',
    '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA7\\nabc+/=\\n-----END RSA PRIVATE KEY-----',
    'Authorization: Bearer Zq9abcDEF123ghiJKL456',
    'Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==',
    'Authorization: Token Zq9abcDEF123ghiJKL456',
    'password=Zq9abcDEF123ghi',
    'api_key: "Zq9abcDEF123ghi"',
    '{"client_secret":"Zq9abcDEF123ghi","ok":true}',
    '{\\"password\\":\\"Zq9abcDEF123ghi\\"}',
    'https://x.test/cb?token=Zq9abcDEF123ghi&x=1',
    'https://x.test/cb?redirect=https%3A%2F%2Fy.test%2F%3Ftoken%3DZq9abcDEF123ghi&z=1',
    'https://x.test/cb?code=Zq9abcDEF123ghi',
    "secret = 'Zq9 abc DEF, 123'",
];

/** Shapes only the full tier (the upstream scanners) is expected to find. */
export const SCANNER_SAMPLES: readonly string[] = [
    `npm_${chars(rng, BASE62, 36)}`,
    `SG.${chars(rng, `${BASE62}_-`, 22)}.${chars(rng, `${BASE62}_-`, 43)}`,
    'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    `lin_api_${chars(rng, BASE62, 40)}`,
    `shpat_${chars(rng, HEX, 32)}`,
    'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'mongodb+srv://admin:Zq9s3cretValue@cluster0.example.test/db',
    `glpat-${chars(rng, `${BASE62}_-`, 20)}`,
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n' +
        '-----END OPENSSH PRIVATE KEY-----',
];
