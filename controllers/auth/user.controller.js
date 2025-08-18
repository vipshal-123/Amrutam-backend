import config from '@/config'
import isEmpty from 'is-empty'
import ms from 'ms'
import * as enums from '@/constants/enums'
import { Security, Token, User } from '@/models'
import { sendOtp, verifyOtp } from '@/security/auth.security'
import { decryptString, encryptString } from '@/security/crypto'
import { comparePassword, generateJWTToken, generatePassword } from '@/security/security'
import { v4 as uuid } from 'uuid'

export const signupSendOtp = async (req, res) => {
    try {
        const { body, cookies, otpCount } = req

        const findUser = await User.findOne({ email: body.email }).select('_id').lean()

        if (!isEmpty(findUser)) {
            return res.status(400).json({ success: false, message: 'User already exist with this email' })
        }

        const userPayload = {
            name: body.name,
            email: body.email,
            role: enums.ROLES.USER,
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
            enums.OTP_SESSIONS.EMAIL_OTP,
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
            tokenId?.session,
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

export const verifySignupOtp = async (req, res) => {
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
            enums.OTP_SESSIONS.EMAIL_OTP,
        )

        if (!status) {
            return res.status(400).json({ success: false, message })
        }

        const updateUser = await User.updateOne({ _id: decryptToken._id }, { $set: { isEmailVerified: true } }).lean()

        if (updateUser.modifiedCount === 0) {
            console.log('updateUser.modifiedCount: ', updateUser)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const cookieData = encryptString(JSON.stringify({ _id: decryptToken._id }))

        const cookieConfig = {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            partitioned: true,
        }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie('create_password_token', cookieData, cookieConfig)
        res.clearCookie('email_otp_session')

        return res.status(201).json({ success: true, message: 'Organization registered successfully', mode: 'CREATE_PASSWORD' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const createPassword = async (req, res) => {
    try {
        const { body, cookies } = req

        if (isEmpty(cookies.create_password_token)) {
            console.log('cookies.create_password_token: ', cookies.create_password_token)
            return res.status(400).json({ success: false, message: 'Invalid session' })
        }

        const decryptData = JSON.parse(decryptString(cookies.create_password_token))

        if (isEmpty(decryptData)) {
            console.log('decryptData: ', decryptData)
            return res.status(400).json({ success: false, message: 'Invalid session' })
        }

        const userData = await User.findById(decryptData._id).lean()

        if (isEmpty(userData)) {
            console.log('userData: ', userData)
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        const findSecurity = await Security.findOne({ userId: userData._id }).select('_id').lean()

        if (isEmpty(findSecurity)) {
            const secPayload = {
                userId: userData._id,
                type: enums.SECURITY_TYPES.ACTIVATION_MAIL,
            }

            const createSecurity = await Security.create(secPayload)

            if (isEmpty(createSecurity)) {
                console.log('createSecurity: ', createSecurity)
                return res.status(500).json({ success: false, message: 'Something went wrong' })
            }
        }

        const hashPassword = await generatePassword(body?.password)

        if (isEmpty(hashPassword)) {
            console.log('hashPassword: ', hashPassword)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const updateUser = await User.updateOne(
            { _id: userData._id },
            { $set: { password: hashPassword, status: enums.STATUS.ACTIVE, isEmailVerified: true } },
        ).lean()

        if (updateUser.modifiedCount === 0) {
            console.log('updateUser: ', updateUser)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const sessionId = uuid()

        const jwtPayload = { sessionId: sessionId, _id: userData._id, role: enums.ROLES.USER, organizationId: null }

        const accessToken = generateJWTToken(jwtPayload, false)
        const refreshToken = generateJWTToken(jwtPayload, true)

        const createToken = await Token.create({
            userId: userData._id,
            role: enums.ROLES.USER,
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
            maxAge: ms(config.REFRESH_TOKEN_EXPIRATION),
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            expiresIn: ms(config.REFRESH_TOKEN_EXPIRATION),
            partitioned: true,
        }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie('refreshToken', refreshToken, cookieConfig)
        res.clearCookie('create_password_token')

        return res.status(200).json({ success: true, message: 'Password created successfully', mode: 'HOME', accessToken })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const signin = async (req, res) => {
    try {
        const { body } = req

        const user = await User.findOne({ email: body.email, role: enums.ROLES.USER }).lean()

        if (isEmpty(user)) {
            return res.status(400).json({ success: false, message: 'No user exists with this email' })
        }

        if (!user.isEmailVerified) {
            return res.status(400).json({ success: false, message: 'E-mail was not verified, please signUp to continue', mode: 'SIGNUP' })
        }

        if (user.status === enums.STATUS.BLOCKED || user.status === enums.STATUS.INACTIVE) {
            return res
                .status(400)
                .json({ success: false, message: `Sorry, your account has been ${user.status.toLowerCase()}, please contact your Admin` })
        }

        const passwordCheck = await comparePassword(body.password, user.password)

        if (!passwordCheck) {
            return res.status(400).json({ success: false, message: 'Password is incorrect' })
        }

        const userSecurity = await Security.findOne({ userId: user._id }).lean()

        if (isEmpty(userSecurity)) {
            return res.status(404).json({ success: false, message: 'Security info not found' })
        }

        const sessionId = uuid()

        const accessToken = generateJWTToken({ sessionId: sessionId, _id: user._id, role: enums.ROLES.USER, organizationId: null }, false)
        const refreshToken = generateJWTToken({ sessionId: sessionId, _id: user._id, role: enums.ROLES.USER, organizationId: null }, true)

        await Token.create({
            userId: user._id,
            role: enums.ROLES.USER,
            sessionId,
            accessToken,
            refreshToken,
            expiresAt: new Date(Date.now() + ms(config.REFRESH_TOKEN_EXPIRATION)),
        })

        // Add tokensInfo to redis

        const cookieConfig = {
            maxAge: ms(config.REFRESH_TOKEN_EXPIRATION),
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            expiresIn: ms(config.REFRESH_TOKEN_EXPIRATION),
            partitioned: true,
        }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie('refreshToken', refreshToken, cookieConfig)

        return res.status(201).json({ success: true, message: 'Signed-In successfully', sessionId, accessToken, role: enums.ROLES.USER })
    } catch (error) {
        console.error('signin', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const signinWithGoogle = async (req, res) => {
    try {
        const { body, cookies } = req

        if (!isEmpty(cookies.create_password_token)) {
            res.clearCookie('create_password_token')
        }

        if (isEmpty(body.token)) {
            return res.status(404).json({ success: false, message: 'Token not found' })
        }

        const response = await config.GoogleClient.verifyIdToken({
            idToken: body.token,
            audience: config.GOOGLE_CLIENT_ID,
        })

        const payload = response.getPayload()
        console.log('payload: ', payload)

        if (isEmpty(payload)) {
            return res.status(400).json({ success: false, message: 'Invalid token, Failed to fetch data from google' })
        }

        const user = await User.findOne({ email: payload.email, role: enums.ROLES.USER }).lean()

        if (!isEmpty(user) && !user.isEmailVerified) {
            return res.status(400).json({ success: false, message: 'E-mail was not verified, please signUp to continue', mode: 'SIGNUP' })
        }

        if (!isEmpty(user) && (user?.status === enums.STATUS.BLOCKED || user?.status === enums.STATUS.INACTIVE)) {
            return res
                .status(400)
                .json({ success: false, message: `Sorry, your account has been ${user.status.toLowerCase()}, please contact your Admin` })
        }

        if (isEmpty(user)) {
            const userPayload = {
                email: payload.email,
                name: payload.name,
                role: enums.ROLES.USER,
            }

            const createUser = await User.create(userPayload)

            if (isEmpty(createUser)) {
                return res.status(500).json({ success: false, message: 'Something went wrong' })
            }

            const cookieData = encryptString(JSON.stringify({ _id: createUser._id }))

            const cookieConfig = {
                httpOnly: true,
                sameSite: 'none',
                secure: true,
                partitioned: true,
            }

            res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
            res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
            res.cookie('create_password_token', cookieData, cookieConfig)

            return res.status(200).json({ success: true, message: 'User signin successfully', mode: 'CREATE_PASSWORD' })
        }

        const sessionId = uuid()

        const accessToken = generateJWTToken({ sessionId: sessionId, _id: user._id, role: enums.ROLES.USER, organizationId: null }, false)
        const refreshToken = generateJWTToken({ sessionId: sessionId, _id: user._id, role: enums.ROLES.USER, organizationId: null }, true)

        await Token.create({
            userId: user._id,
            role: enums.ROLES.USER,
            sessionId,
            accessToken,
            refreshToken,
            expiresAt: new Date(Date.now() + ms(config.REFRESH_TOKEN_EXPIRATION)),
        })

        const cookieConfig = {
            maxAge: ms(config.REFRESH_TOKEN_EXPIRATION),
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            expiresIn: ms(config.REFRESH_TOKEN_EXPIRATION),
            partitioned: true,
        }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie('refreshToken', refreshToken, cookieConfig)

        return res.status(200).json({ success: true, message: 'User signin successfully', mode: 'HOME', accessToken })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
