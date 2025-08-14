import isEmpty from 'is-empty'
import ms from 'ms'
import moment from 'moment'
import config from '@/config'
import { generateOTP } from '@/utils/reUseableFunctions'
import { v4 as uuid } from 'uuid'
import { encryptString } from './crypto'
import { sendEmailViaTemplate } from '@/controllers/utility/mail.controller'
import { compareString, hashString } from './security'
import { Security } from '@/models'

export const sendOtp = async (user, res, cookies, identifier, subject = '', type, mode, session, otpCount) => {
    try {
        if (!isEmpty(cookies[session])) {
            res.clearCookie(session)
        }

        const otp = generateOTP()
        console.log('otp: ', otp)
        const otpExpiry = new Date(Date.now() + ms('10min'))
        const otpSecret = uuid()

        const otpHash = await hashString(otpSecret)

        if (!otpHash) {
            return { status: false, message: 'Something went wrong' }
        }

        const emailContext = {
            identifier: identifier,
            to: user.email,
            content: {
                subject: subject,
                otp: otp,
            },
        }
        const emailSent = await sendEmailViaTemplate(emailContext)

        if (!emailSent) {
            console.log('emailSent: ', emailSent)
            return { status: false, message: 'Something went wrong' }
        }

        const otpValueHash = await hashString(otp)

        const filterObject = {
            value: otpValueHash,
            userId: user._id,
            type: type,
            mode: mode,
            expiresAt: otpExpiry,
            secret: otpSecret,
            securityCount: otpCount,
            otpRequestedAt: moment().toDate(),
        }

        const updateSecurity = await Security.updateOne({ userId: user._id, type: type, mode: mode }, { $set: filterObject }, { upsert: true }).lean()

        if (updateSecurity.modifiedCount === 0 && updateSecurity.upsertedCount === 0) {
            console.log('updateSecurity: ', updateSecurity)
            return { status: false, message: 'Something went wrong' }
        }

        const token = encryptString(JSON.stringify({ _id: user._id, email: user.email, type: type, mode: mode, session: session }))

        const cookieConfig = {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            partitioned: true,
        }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie(session, otpHash, cookieConfig)

        return { status: true, token: token }
    } catch (error) {
        console.error('OTP verification error:', error)
        return { status: false, message: 'Something went wrong' }
    }
}

export const verifyOtp = async (user, res, cookies, otp, type, mode, session) => {
    console.log('session: ', session)
    console.log('mode: ', mode)
    console.log('type: ', type)
    try {
        if (isEmpty(cookies[session])) {
            return { status: false, message: 'Invalid cookie session' }
        }

        if (isEmpty(otp)) {
            return { status: false, message: 'Otp is required' }
        }

        const securityData = await Security.findOne({ userId: user._id, type: type, mode: mode }).lean()
        console.log('securityData: ', securityData)

        if (isEmpty(securityData)) {
            console.log('securityData: ', securityData)
            return { status: false, message: 'Otp verification failed, retry with new OTP' }
        }

        if (isEmpty(securityData?.secret)) {
            console.log('securityData: ', securityData)
            return { status: false, message: 'Otp verification failed, retry with new OTP' }
        }

        if (!(await compareString(securityData.secret, cookies[session]))) {
            return { status: false, message: 'Invalid session' }
        }

        const now = moment()
        console.log('now: ', now)
        const otpResetTime = moment(securityData?.otpRequestedAt).add(6, 'hours')
        console.log('otpResetTime: ', otpResetTime)
        console.log('securityData?.tries: ', securityData?.tries)

        if (securityData?.tries >= 5 && now.isBefore(otpResetTime)) {
            const waitHours = otpResetTime.diff(now, 'hours')
            const waitMinutes = otpResetTime.diff(now, 'minutes') % 60
            const waitTimeFormatted = `${waitHours} hours ${waitMinutes} minutes.`
            return { status: false, message: `You have reached the maximum OTP tries. Please try again after ${waitTimeFormatted}` }
        }

        if (!(await compareString(otp, securityData.value))) {
            const updateSecurity = await Security.updateOne(
                { userId: user._id, type: type, mode: mode },
                { $set: { tries: securityData?.tries + 1 } },
            )

            if (updateSecurity.modifiedCount === 0) {
                console.log('Failed to update user security')
                return { status: false, message: 'Something went wrong' }
            }
            return { status: false, message: 'Invalid OTP' }
        }

        if (new Date() > securityData.expiresAt) {
            return { status: false, message: 'Your OTP has been expired' }
        }

        const updateData = {
            value: '',
            expiresAt: null,
            secret: null,
            tries: 0,
            securityCount: 0,
            otpRequestedAt: null,
        }

        const updateSecurity = await Security.updateOne({ userId: user._id, type: type }, { $set: updateData })

        if (updateSecurity.modifiedCount === 0) {
            console.log('updateSecurity: ', updateSecurity)
            return { status: false, message: 'Something went wrong' }
        }
        res.clearCookie(session)

        return { status: true }
    } catch (error) {
        console.error('OTP verification error:', error)
        return { status: false, message: 'Something went wrong' }
    }
}
