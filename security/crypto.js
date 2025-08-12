import crypto from 'crypto'
import config from '@/config'

export const encryptString = (text) => {
    const iv = crypto.randomBytes(16)
    const key = crypto.createHash('sha256').update(config.CRYPTO_SECRET).digest('base64').substr(0, 32)
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv)
    const stringData = typeof text === 'string' ? text : text.toString()

    let encrypted = cipher.update(stringData, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    return `${iv.toString('hex')}:${encrypted}`
}

export const decryptString = (encryptedText) => {
    const [iv, encrypted] = encryptedText.split(':')

    const key = crypto.createHash('sha256').update(config.CRYPTO_SECRET).digest('base64').substr(0, 32)
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv, 'hex'))
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
}
