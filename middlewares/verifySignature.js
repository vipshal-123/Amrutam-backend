import crypto from 'crypto'
import config from '@/config'
import isEmpty from 'is-empty'

/**
 * Important Params,
 */
export const verifySignature = async (req, res, next) => {
    try {
        return next()
    } catch (error) {
        console.log(error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
