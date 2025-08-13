import jsonwebtoken from 'jsonwebtoken'
import config from '@/config'
import { Admin, Token, User } from '@/models'
import * as enums from '@/constants/enums'
import isEmpty from 'is-empty'

export const userAuthenticate = async (req, res, next) => {
    try {
        const isRefreshing = req.path.endsWith('/refresh-token')

        const token = isRefreshing ? req.cookies.refreshToken : req.headers.authorization.split(' ')[1]
        const decoded = jsonwebtoken.verify(token, config.AUTH_PUBLIC_KEY, { algorithms: ['RS256'] })
        // console.log('decoded: ', decoded);
        const user = await User.findById(decoded._id).select('_id status').lean()

        const tokenRecord = await Token.findOne({ [isRefreshing ? 'refreshToken' : 'accessToken']: token }).lean()

        if (!tokenRecord) {
            return res.status(401).json({ success: false, message: 'Unauthorized' })
        }

        if (isEmpty(user)) {
            return res.status(401).json({ success: false, message: 'Unauthorized' })
        }

        if (user.status !== enums.STATUS.ACTIVE) {
            return res.status(401).json({ success: false, message: 'Unauthorized' })
        }

        req.user = decoded
        req.user.sessionId = tokenRecord.sessionId

        return next()
    } catch (error) {
        console.log(error.message)
        return res.status(401).json({ success: false, message: 'Unauthorized' })
    }
}

export const decodeRefresh = (token) => {
    try {
        return jsonwebtoken.verify(token, config.AUTH_PUBLIC_KEY, { algorithms: ['RS256'] })
    } catch (error) {
        console.error('error: ', error)
    }
}
