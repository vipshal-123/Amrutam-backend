import { Security, User } from '@/models'
import { decryptString } from '@/security/crypto'
import isEmpty from 'is-empty'
import moment from 'moment'

export const limitOtp = async (req, res, next) => {
    try {
        const { body, user } = req

        let userData = {}

        if (!isEmpty(user?._id)) {
            userData = await User.findById(user._id).lean()
        }

        if (!isEmpty(body.email) && isEmpty(user?._id)) {
            userData = await User.findOne({ email: body.email }).lean()
        }

        if (isEmpty(userData) && !isEmpty(body?.token)) {
            const decodeData = JSON.parse(decryptString(body?.token))
            console.log('decodeData: ', decodeData)
            userData = await User.findById(decodeData?._id).lean()
        }

        const securityData = await Security.findOne({ userId: userData?._id })

        const now = moment()
        console.log('now: ', now)
        const otpResetTime = moment(securityData?.otpRequestedAt).add(6, 'hours')
        console.log('otpResetTime: ', otpResetTime)

        if (securityData?.securityCount >= 5 && now.isBefore(otpResetTime)) {
            const waitHours = otpResetTime.diff(now, 'hours')
            const waitMinutes = otpResetTime.diff(now, 'minutes') % 60
            const waitTimeFormatted = `${waitHours} hours ${waitMinutes} minutes.`
            return res
                .status(400)
                .json({ success: false, message: `You have reached the maximum OTP requests. Please try again after ${waitTimeFormatted}` })
        }

        const updatedCount = now.isAfter(otpResetTime) ? 1 : (securityData?.securityCount || 0) + 1

        req.otpCount = updatedCount
        return next()
    } catch (error) {
        console.error('Error in limitOtp middleware: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
