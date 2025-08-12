import isEmpty from 'is-empty'
import * as enums from '@/constants/enums'
import { Organization, Security, Token, User } from '@/models'
import { sendOtp, verifyOtp } from '@/security/auth.security'
import { decryptString } from '@/security/crypto'
import { v4 as uuid } from 'uuid'
import ms from 'ms'
import { generateJWTToken } from '@/security/security'
import config from '@/config'

export const createOrgSendOtp = async (req, res) => {
    try {
        const { body, cookies, otpCount } = req

        const findUser = await User.findOne({ email: body.email }).select('_id').lean()

        if (!isEmpty(findUser)) {
            return res.status(400).json({ success: false, message: 'User already exist with this email' })
        }

        const findOrg = await Organization.findOne({ email: body.email }).select('_id').lean()

        if (!isEmpty(findOrg)) {
            return res.status(400).json({ success: false, message: 'Org already exist with this email' })
        }

        const userPayload = {
            name: body.name,
            email: body.email,
            role: enums.ROLES.ORG_ADMIN,
        }

        const createUser = await User.create(userPayload)

        if (isEmpty(createUser)) {
            console.log('createUser: ', createUser)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const { status, message, token } = await sendOtp(
            { _id: createUser._id, email: createUser.email },
            res,
            cookies,
            enums.EMAIL_CATEGORIES.OTP_TEMPLATE,
            '',
            enums.SECURITY_TYPES.ACTIVATION_MAIL,
            enums.SECURITY_MODES.EMAIL,
            otpCount,
        )

        if (!status) {
            console.log('message: ', message)
            return res.status(500).json({ success: false, message: 'Something went wrong while sending otp' })
        }

        return res.status(200).json({ success: true, message: 'Otp send via email', mode: 'OTP_VERIFY', token })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const resendOtp = async (req, res) => {
    try {
        const { body, otpCount, cookies } = req
        console.log('otpCount: ', otpCount)

        if (isEmpty(body.token)) {
            return res.status(400).json({ success: false, message: 'Token is required' })
        }

        const tokenId = JSON.parse(decryptString(body.token))
        const user = await User.findById(tokenId?._id).select('_id').lean()

        if (isEmpty(user)) {
            console.log('user: ', user)
            return res.status(400).json({ success: false, message: 'Invalid token' })
        }

        const securityData = await Security.findOne({ userId: user._id, type: tokenId?.type, mode: tokenId?.mode })

        if (isEmpty(securityData)) {
            return res.status(404).json({ success: false, message: 'Security not found' })
        }

        if (securityData.expiresAt - new Date() > ms('8m')) {
            return res.status(400).json({ success: false, message: 'Please try requesting OTP after two minutes' })
        }

        const { status, message } = await sendOtp(
            { _id: tokenId._id, email: tokenId.email },
            res,
            cookies,
            enums.EMAIL_CATEGORIES.OTP_TEMPLATE,
            '',
            tokenId?.type,
            tokenId?.mode,
            otpCount,
        )

        if (!status) {
            console.log('message: ', message)
            return res.status(500).json({ success: false, message: 'Something went wrong while sending otp' })
        }
        return res.status(201).json({ success: true, message: 'OTP has been successfully resent to your email', mode: 'VERIFY_SIGNUP' })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const createOrgVerifyOtp = async (req, res) => {
    try {
        const { body, cookies } = req

        if (isEmpty(body?.token)) {
            return res.status(400).json({ success: false, message: 'Invalid token' })
        }

        const decryptToken = JSON.parse(decryptString(body.token))

        if (isEmpty(decryptToken)) {
            return res.status(400).json({ success: false, message: 'Invalid token' })
        }

        const { status, message } = await verifyOtp(
            { _id: decryptToken._id },
            res,
            cookies,
            body.otp,
            enums.SECURITY_TYPES.ACTIVATION_MAIL,
            enums.SECURITY_MODES.EMAIL,
        )

        if (!status) {
            return res.status(400).json({ success: false, message })
        }

        const updateUser = await User.updateOne({ _id: decryptToken._id }, { $set: { isEmailVerified: true } }).lean()

        if (updateUser.modifiedCount === 0) {
            console.log('updateUser.modifiedCount: ', updateUser)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const payload = {
            createdBy: decryptToken._id,
            name: body.name,
            email: body.email,
            type: body.type,
            address: body.address,
            city: body.city,
            state: body.state,
            country: body.country,
            pincode: body.pincode,
            contactPerson: body.contactPerson,
            phone: body.phone,
            description: body?.description || '',
        }

        const createOrg = await Organization.create(payload)

        if (isEmpty(createOrg)) {
            console.log('createOrg: ', createOrg)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const sessionId = uuid()

        const jwtPayload = { sessionId: sessionId, _id: decryptToken._id, role: enums.ROLES.ORG_ADMIN }

        const accessToken = generateJWTToken(jwtPayload, false)
        const refreshToken = generateJWTToken(jwtPayload, true)

        const createToken = await Token.create({
            userId: decryptToken._id,
            role: enums.ROLES.ORG_ADMIN,
            sessionId: sessionId,
            accessToken,
            refreshToken,
            expiresAt: new Date(Date.now() + ms(config.REFRESH_TOKEN_EXPIRATION)),
        })

        if (isEmpty(createToken)) {
            console.log('createToken: ', createToken)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const cookieConfig = {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            partitioned: true,
        }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie('refreshToken', refreshToken, cookieConfig)
        res.clearCookie('email_otp_session')

        return res.status(201).json({
            success: true,
            message: 'Organization registered successfully',
            sessionId,
            accessToken,
            role: enums.ROLES.ORG_ADMIN,
            mode: 'ADD_USERS',
        })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
