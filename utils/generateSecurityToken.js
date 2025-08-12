import crypto from 'crypto-js'

const generateSecurityToken = () => {
    const token = crypto.lib.WordArray.random(64).toString()
    return token
}

export default generateSecurityToken
