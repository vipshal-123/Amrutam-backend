import jsonwebtoken from 'jsonwebtoken'
import config from '@/config'
import { Admin, Token, User } from '@/models'
import * as enums from '@/constants/enums'

export const userAuthenticate = async (req, res, next) => {
    try {
        const isRefreshing = req.path.endsWith('/refresh-token')

        const token = isRefreshing ? req.cookies.refreshToken : req.headers.authorization.split(' ')[1]
        const decoded = jsonwebtoken.verify(token, config.AUTH_PUBLIC_KEY, { algorithms: ['RS256'] })
        // console.log('decoded: ', decoded);
        let adminUser = null

        if (decoded?.role === enums.ADMIN_ROLES.USER) {
            adminUser = await User.findById(decoded._id).lean()
        } else {
            adminUser = await Admin.findById(decoded._id, { password: 0 }).lean()
        }

        const tokenRecord = await Token.findOne({ [isRefreshing ? 'refreshToken' : 'accessToken']: token }).lean()

        if (!tokenRecord) {
            return res.status(401).json({ success: false, message: 'Unauthorized' })
        }

        if (!adminUser) {
            return res.status(401).json({ success: false, message: 'Unauthorized' })
        }

        if (tokenRecord.isSessionEnded) {
            return res.status(401).json({ success: false, message: 'Unauthorized' })
        }

        if (adminUser.status !== enums.ADMIN_STATES.ACTIVE) {
            return res.status(401).json({ success: false, message: 'Unauthorized' })
        }

        req.user = adminUser
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
