import isEmpty from 'is-empty'
import * as enums from '@/constants/enums'
import { DoctorInfo, Organization, Security, Specialization, Token, User } from '@/models'
import { sendOtp, verifyOtp } from '@/security/auth.security'
import { decryptString } from '@/security/crypto'
import { v4 as uuid } from 'uuid'
import ms from 'ms'
import { comparePassword, compareString, generateJWTToken, generatePassword, hashString } from '@/security/security'
import config from '@/config'
import moment from 'moment'
import { sendEmailViaTemplate } from '../utility/mail.controller'
import { parsePhoneNumberWithError } from 'libphonenumber-js'

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
            enums.OTP_SESSIONS.EMAIL_OTP,
        )

        if (!status) {
            return res.status(400).json({ success: false, message })
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

        const updateUser = await User.updateOne(
            { _id: decryptToken._id },
            { $set: { isEmailVerified: true, status: enums.STATUS.ACTIVE, organizationId: createOrg._id } },
        ).lean()

        if (updateUser.modifiedCount === 0) {
            console.log('updateUser.modifiedCount: ', updateUser)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const sessionId = uuid()

        const jwtPayload = { sessionId: sessionId, _id: decryptToken._id, role: enums.ROLES.ORG_ADMIN, organizationId: createOrg._id }

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
            maxAge: ms(config.REFRESH_TOKEN_EXPIRATION),
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            partitioned: true,
            expiresIn: ms(config.REFRESH_TOKEN_EXPIRATION),
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

export const addDoctors = async (req, res) => {
    try {
        const { user, body } = req

        try {
            const parsedNumber = parsePhoneNumberWithError(body?.contact, 'IN')
            if (!parsedNumber.isValid() || !parsedNumber.isPossible()) {
                return res.status(400).json({ success: false, errors: { phoneNumber: 'Invalid Phone number' } })
            }
        } catch (error) {
            console.error('error: ', error)
            return res.status(400).json({ success: false, errors: { phoneNumber: 'Invalid Phone number' } })
        }

        const userPayload = {
            email: body?.email,
            name: body?.name,
            addedBy: user?._id,
            organizationId: user.organizationId,
            role: enums.ROLES.DOCTOR,
        }

        const createUser = await User.create(userPayload)

        if (isEmpty(createUser)) {
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const doctorInfoPayload = {
            organizationId: user.organizationId,
            userId: createUser._id,
            specialization: body?.specialization,
            availability: body?.mode,
            experience: body?.experience,
            contact: body?.contact,
            bio: body?.bio,
        }

        const createDoctorInfo = await DoctorInfo.create(doctorInfoPayload)

        if (isEmpty(createDoctorInfo)) {
            await User.deleteOne({ _id: createUser._id }).lean()
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const findSpec = await Specialization.findById(body?.specialization).select('title').lean()

        const token = uuid()

        const hash = await hashString(token)

        const emailContext = {
            identifier: 'SEND_LINK_TEMPLATE',
            to: body.email,
            content: {
                subject: 'User verification link',
                link: `${config.FRONTEND_USER}/doc-create-password?token=${token}`,
                email: body.email,
            },
        }

        const createSecurity = await Security.create({
            userId: createUser._id,
            type: enums.SECURITY_TYPES.ACTIVATION_MAIL,
            value: token,
            secret: hash,
            expiresAt: moment().add(1, 'day'),
        })

        if (isEmpty(createSecurity)) {
            console.log('createSecurity: ', createSecurity)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const emailSent = await sendEmailViaTemplate(emailContext)

        if (!emailSent) {
            console.log('emailSent: ', emailSent)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({
            success: true,
            message: 'Doctor added successfully, check mail for the login link',
            _id: createDoctorInfo._id,
            specialization: findSpec?.title || '',
        })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const resendAddDoctorsMail = async (req, res) => {
    try {
        const { body } = req

        const findUser = await User.findById(body.userId).select('_id').lean()

        if (isEmpty(findUser)) {
            return res.status(404).json({ success: false, message: 'User not found' })
        }

        const token = uuid()

        const hash = await hashString(token)

        const emailContext = {
            identifier: 'SEND_LINK_TEMPLATE',
            to: body.email,
            content: {
                subject: 'User verification link',
                link: `${config.FRONTEND_USER}/doc-create-password?token=${token}`,
                email: body.email,
            },
        }

        const createSecurity = await Security.updateOne(
            { type: enums.SECURITY_TYPES.ACTIVATION_MAIL, userId: findUser._id },
            {
                $set: {
                    value: token,
                    secret: hash,
                    expiresAt: moment().add(1, 'day'),
                },
            },
        ).lean()

        if (createSecurity.modifiedCount === 0) {
            console.log('createSecurity: ', createSecurity)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const emailSent = await sendEmailViaTemplate(emailContext)

        if (!emailSent) {
            console.log('emailSent: ', emailSent)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Doctor added successfully, check mail for the login link' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const verifyDocMail = async (req, res) => {
    try {
        const { body } = req

        if (isEmpty(body?.token)) {
            return res.status(404).json({ success: false, message: 'Token not found' })
        }

        const findSecurity = await Security.findOne({ type: enums.SECURITY_TYPES.ACTIVATION_MAIL, value: body?.token })
        console.log('findSecurity: ', findSecurity)

        if (isEmpty(findSecurity)) {
            return res.status(400).json({ success: false, message: 'Session not found' })
        }

        if (moment(findSecurity?.expiresAt).isBefore(moment().toDate())) {
            await Security.deleteMany({ type: enums.SECURITY_TYPES.ACTIVATION_MAIL, value: body?.token })
            return res.status(400).json({ success: false, message: 'Session expired, ask admin to resend it' })
        }

        const findUser = await User.findById(findSecurity.userId).select('_id isEmailVerified').lean()

        if (isEmpty(findUser)) {
            return res.status(404).json({ success: false, message: 'User not found' })
        }

        if (findUser.isEmailVerified) {
            return res.status(400).json({ success: false, message: 'E-mail already verified' })
        }

        const status = await compareString(findSecurity?.value, findSecurity.secret)

        if (!status) {
            console.log('status: ', status)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const hashPassword = await generatePassword(body?.password)

        const updateUser = await User.updateOne(
            { _id: findUser._id },
            { $set: { isEmailVerified: true, password: hashPassword, status: enums.STATUS.ACTIVE } },
        ).lean()

        if (updateUser.modifiedCount === 0) {
            console.log('updateUser: ', updateUser)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const updateSecurity = await Security.updateOne(
            { type: enums.SECURITY_TYPES.ACTIVATION_MAIL, userId: findSecurity.userId },
            { $set: { value: '', secret: '', expiresAt: null } },
        ).lean()

        if (updateSecurity.modifiedCount === 0) {
            console.log('updateSecurity: ', updateSecurity)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Doctor verified successfully, signin to continue', mode: 'SIGNIN' })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const doctorSignin = async (req, res) => {
    try {
        const { body } = req

        const user = await User.findOne({ email: body.email, role: enums.ROLES.DOCTOR }).lean()

        if (isEmpty(user)) {
            return res.status(400).json({ success: false, message: 'No doctor exists with this email' })
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

        const accessToken = generateJWTToken(
            { sessionId: sessionId, _id: user._id, role: enums.ROLES.DOCTOR, organizationId: user.organizationId },
            false,
        )
        const refreshToken = generateJWTToken(
            { sessionId: sessionId, _id: user._id, role: enums.ROLES.DOCTOR, organizationId: user.organizationId },
            true,
        )

        await Token.create({
            userId: user._id,
            role: enums.ROLES.DOCTOR,
            sessionId,
            accessToken,
            refreshToken,
            expiresAt: new Date(Date.now() + ms(config.REFRESH_TOKEN_EXPIRATION)),
        })

        // Add tokensInfo to redis

        const cookieConfig = body.isRemember
            ? {
                  maxAge: ms(config.REFRESH_TOKEN_EXPIRATION),
                  httpOnly: true,
                  sameSite: 'none',
                  secure: true,
                  expiresIn: ms(config.REFRESH_TOKEN_EXPIRATION),
                  partitioned: true,
              }
            : {
                  httpOnly: true,
                  sameSite: 'none',
                  secure: true,
                  partitioned: true,
              }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie('refreshToken', refreshToken, cookieConfig)

        return res.status(201).json({ success: true, message: 'Signed-In successfully', sessionId, accessToken, role: enums.ROLES.DOCTOR })
    } catch (error) {
        console.error('signin', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const orgAdminLoginSendOtp = async (req, res) => {
    try {
        const { body, cookies, otpCount } = req

        const findUser = await User.findOne({ email: body.email, role: enums.ROLES.ORG_ADMIN }).select('_id role email isEmailVerified').lean()

        if (isEmpty(findUser)) {
            return res.status(400).json({ success: false, message: 'Org admin with this email not exist' })
        }

        if (findUser.role !== enums.ROLES.ORG_ADMIN) {
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        if (!findUser.isEmailVerified) {
            return res.status(400).json({ success: false, message: 'E-mail was not verified, please signUp to continue', mode: 'SIGNUP' })
        }

        const { status, message, token } = await sendOtp(
            { _id: findUser._id, email: findUser.email },
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
        console.error('signin', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const orgAdminVerifyOtp = async (req, res) => {
    try {
        const { body, cookies } = req

        if (isEmpty(body?.token)) {
            return res.status(400).json({ success: false, message: 'Invalid token' })
        }

        const decryptToken = JSON.parse(decryptString(body.token))

        if (isEmpty(decryptToken)) {
            return res.status(400).json({ success: false, message: 'Invalid token' })
        }

        const findUser = await User.findById(decryptToken._id).select('_id organizationId')

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

        const sessionId = uuid()

        const jwtPayload = { sessionId: sessionId, _id: decryptToken._id, role: enums.ROLES.ORG_ADMIN, organizationId: findUser.organizationId }

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
            maxAge: ms(config.REFRESH_TOKEN_EXPIRATION),
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            partitioned: true,
            expiresIn: ms(config.REFRESH_TOKEN_EXPIRATION),
        }

        res.header('Access-Control-Allow-Origin', config.FRONTEND_USER)
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
        res.cookie('refreshToken', refreshToken, cookieConfig)
        res.clearCookie('email_otp_session')

        return res.status(200).json({
            success: true,
            message: 'Signin successfully',
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
