import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import config from '@/config'
import ms from 'ms'

export const generatePassword = async (password) => {
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    return hashedPassword
}

export const comparePassword = async (password, hashedPassword) => {
    const isMatch = await bcrypt.compare(password, hashedPassword)
    return isMatch
}

export const generateJWTToken = (payload, isRefreshToken = false) => {
    const token = jwt.sign(payload, config.AUTH_SIGNER_KEY, {
        algorithm: 'RS256',
        expiresIn: ms(isRefreshToken ? config.REFRESH_TOKEN_EXPIRATION : config.ACCESS_TOKEN_EXPIRATION) / 1000,
    })

    return token
}

export const hashString = async (string) => {
    const salt = await bcrypt.genSalt(10)
    const hashedString = await bcrypt.hash(string, salt)
    return hashedString
}

export const compareString = async (string, hashedString) => {
    const isMatch = await bcrypt.compare(string, hashedString)
    return isMatch
}
