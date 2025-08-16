import fs from 'fs'
import { OAuth2Client } from 'google-auth-library'
import path from 'path'

const config = {
    PORT: process.env.PORT,
    MONGO_URI: process.env.MONGO_URI,

    // CORS origins
    CORS_ORIGIN: ['http://localhost:3000', 'https://vipshal-123.github.io', 'https://amrutam-frontend.onrender.com'],

    // API Hosts
    API_HOST: process.env.API_HOST,

    // Frontend post
    FRONTEND_USER: 'https://amrutam-frontend.onrender.com',

    // MAIL INFO
    SMTP_MAIL: process.env.MAIL,
    SMTP_HOST: process.env.HOST,
    SMTP_PORT: process.env.MAILPORT,
    SMTP_SECURE: process.env.SECURE,
    SMTP_USER: process.env.USER_NAME,
    SMTP_PASS: process.env.PASSWORD,

    // OTHER UTILITIES
    REQUEST_TIMEOUT: 5000,

    // AUTH PEM KEY
    AUTH_PRIVATE_KEY: fs.readFileSync(path.resolve(path.join(__dirname, '../private/auth_private_key.pem')), 'utf8'),
    AUTH_PUBLIC_KEY: fs.readFileSync(path.resolve(path.join(__dirname, '../private/auth_public_key.pem')), 'utf8'),
    AUTH_SIGNER_KEY: fs.readFileSync(path.resolve(path.join(__dirname, '../private/auth_private_signer.pem')), 'utf8'),

    // AWS KEYS
    AWS_S3_REGION: process.env.AWS_S3_REGION,
    AWS_S3_PUBLIC: process.env.AWS_S3_PUBLIC,
    AWS_S3_PRIVATE: process.env.AWS_S3_PRIVATE,
    AWS_S3_ACCESS: process.env.AWS_S3_ACCESS,
    AWS_S3_SECRET: process.env.AWS_S3_SECRET,

    // CRYPTO ENCRYPTION KEY
    CRYPTO_SECRET: process.env.CRYPTO_SECRET,

    // EXPIRATIONS
    ACCESS_TOKEN_EXPIRATION: '1d',
    REFRESH_TOKEN_EXPIRATION: '30d',
    OTP_EXPIRATION: '3m',

    // ASSETS URL
    ASSETS_URL: process.env.ASSETS_URL,

    // Google OAuth
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI: process.env.FRONTEND_USER,
    GoogleClient: new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, 'https://amrutam-frontend.onrender.com'),

    // S3 Keys
    RATINGS_IMAGES: 'ratings',

    // FILE SIZE
    MAX_PROFILE_FILE_SIZE: 500 * 1024, // 500KB
    MAX_COVER_FILE_SIZE: 1.5 * 1024 * 1024, // 1.5MB
    MAX_RATINGS_FILE_SIZE: 1.5 * 1024 * 1024, // 1.5MB
    MAX_POSTATTACHMENT_FILE_SIZE: 15 * 1024 * 1024, // 15MB
}

export default config
