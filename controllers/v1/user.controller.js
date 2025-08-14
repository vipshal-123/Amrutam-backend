import isEmpty from 'is-empty'
import * as enums from '@/constants/enums'
import mongoose from 'mongoose'
import { BookedSlot, DocAvailability, User } from '@/models'
import { sendOtp, verifyOtp } from '@/security/auth.security'
import { decryptString } from '@/security/crypto'
import moment from 'moment'

export const userInfo = async (req, res) => {
    try {
        const { user } = req

        if (isEmpty(user)) {
            return res.status(200).json({ success: true, data: {} })
        }

        const formattedData = {
            _id: user._id,
            organizationId: user?.organizationId || null,
            role: user.role,
        }

        return res.status(200).json({ success: true, data: formattedData })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const doctorList = async (req, res) => {
    try {
        const { user, query } = req
        console.log('user: ', user)

        if (user.role !== enums.ROLES.USER) {
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        let dbQuery = {
            $expr: { $eq: ['$role', enums.ROLES.DOCTOR] },
            status: enums.STATUS.ACTIVE,
        }
        console.log('dbQuery: ', dbQuery)

        if (!isEmpty(query?.next)) {
            const decodeData = JSON.parse(Buffer.from(query.next, 'base64').toString('utf-8'))
            dbQuery = { ...dbQuery, _id: { $lt: new mongoose.Types.ObjectId(decodeData._id) } }
        }

        console.log('dbQuery: ', dbQuery)

        const aggregationQuery = [
            {
                $match: dbQuery,
            },
            {
                $sort: {
                    _id: -1,
                },
            },
            {
                $limit: parseInt(query?.limit || 10),
            },
            {
                $lookup: {
                    from: 'doctorInfo',
                    localField: '_id',
                    foreignField: 'userId',
                    as: 'doctorInfo',
                },
            },
            {
                $unwind: {
                    path: '$doctorInfo',
                    preserveNullAndEmptyArrays: true,
                },
            },
            {
                $project: {
                    _id: 1,
                    name: 1,
                    email: 1,
                    specialization: '$doctorInfo.specialization',
                    experience: '$doctorInfo.experience',
                    mode: '$doctorInfo.availability',
                    bio: '$doctorInfo.bio',
                    status: 1,
                    isEmailVerified: 1,
                },
            },
        ]

        const findDoctors = await User.aggregate(aggregationQuery)
        console.log('findDoctors: ', findDoctors)

        if (isEmpty(findDoctors)) {
            return res.status(200).json({ success: true, data: [], next: '' })
        }

        const lastData = findDoctors[findDoctors.length - 1]._id
        const encodeData = Buffer.from(JSON.stringify({ _id: lastData }), 'utf-8').toString('base64')

        return res.status(200).json({ success: true, data: findDoctors, next: encodeData })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const singleDoctor = async (req, res) => {
    try {
        const { user, params } = req
        console.log('user: ', user)

        if (user.role !== enums.ROLES.USER) {
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        const aggregationQuery = [
            {
                $match: {
                    _id: new mongoose.Types.ObjectId(params.id),
                },
            },
            {
                $lookup: {
                    from: 'doctorInfo',
                    localField: '_id',
                    foreignField: 'userId',
                    as: 'doctorInfo',
                },
            },
            {
                $unwind: {
                    path: '$doctorInfo',
                    preserveNullAndEmptyArrays: true,
                },
            },
            {
                $lookup: {
                    from: 'docAvailability',
                    localField: '_id',
                    foreignField: 'doctorId',
                    as: 'docAvailability',
                },
            },
            {
                $project: {
                    _id: 1,
                    name: 1,
                    email: 1,
                    specialization: '$doctorInfo.specialization',
                    experience: '$doctorInfo.experience',
                    mode: '$doctorInfo.availability',
                    bio: '$doctorInfo.bio',
                    status: 1,
                    isEmailVerified: 1,
                    docAvailability: 1,
                },
            },
        ]

        const findDoctors = await User.aggregate(aggregationQuery)
        console.log('findDoctors: ', findDoctors)

        if (isEmpty(findDoctors[0])) {
            return res.status(200).json({ success: true, data: {} })
        }

        return res.status(200).json({ success: true, data: findDoctors[0] })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const getBookingSlots = async (req, res) => {
    try {
        const { params } = req

        const aggregationQuery = [
            {
                $match: {
                    _id: new mongoose.Types.ObjectId(params.id),
                },
            },
            {
                $lookup: {
                    from: 'doctorInfo',
                    localField: '_id',
                    foreignField: 'userId',
                    as: 'doctorInfo',
                },
            },
            {
                $unwind: {
                    path: '$doctorInfo',
                    preserveNullAndEmptyArrays: true,
                },
            },
            {
                $lookup: {
                    from: 'docAvailability',
                    localField: '_id',
                    foreignField: 'doctorId',
                    as: 'docAvailability',
                },
            },
            {
                $project: {
                    _id: 1,
                    name: 1,
                    specialization: '$doctorInfo.specialization',
                    bio: '$doctorInfo.bio',
                    docAvailability: 1,
                },
            },
        ]

        const bookingData = await User.aggregate(aggregationQuery)

        if (isEmpty(bookingData?.[0])) {
            return res.status(200).json({ success: true, data: {} })
        }

        return res.status(200).json({ success: true, data: bookingData[0] })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const slotBookingSendOtp = async (req, res) => {
    try {
        const { user, body, cookies, otpCount } = req

        const findAvailability = await DocAvailability.findById(body?.availabilityId).select('_id lockedAt isLocked').lean()

        if (isEmpty(findAvailability)) {
            console.log('findAvailability: ', findAvailability)
            return res.status(400).json({ success: false, message: 'Invalid availability id' })
        }

        if (findAvailability.isLocked) {
            return res.status(400).json({ success: false, message: 'Slot was already locked' })
        }

        if (
            !isEmpty(findAvailability?.lockedAt) &&
            moment().diff(moment(findAvailability.lockedAt), 'minutes') >= 0 &&
            moment().diff(moment(findAvailability.lockedAt), 'minutes') <= 10
        ) {
            return res.status(400).json({ success: false, message: 'Slot was already locked' })
        }

        const { status, message, token } = await sendOtp(
            { _id: user._id, email: body.email },
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

        const updateAvailabilityTime = await DocAvailability.updateOne(
            { _id: body?.availabilityId },
            { $set: { lockedAt: moment().toDate() } },
        ).lean()

        if (updateAvailabilityTime.modifiedCount === 0) {
            console.log('updateAvailabilityTime: ', updateAvailabilityTime)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Otp send to your mail', token })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const slotBookingVerifyOtp = async (req, res) => {
    try {
        const { user, body, cookies } = req

        if (isEmpty(body?.token)) {
            return res.status(400).json({ success: false, message: 'Token is required' })
        }

        const findAvailability = await DocAvailability.findById(body?.availabilityId).select('_id').lean()

        if (isEmpty(findAvailability)) {
            console.log('findAvailability: ', findAvailability)
            return res.status(400).json({ success: false, message: 'Invalid availability id' })
        }

        const decryptToken = JSON.parse(decryptString(body?.token))
        console.log('decryptToken: ', decryptToken);

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
            console.log('status: ', status);
            return res.status(400).json({ success: false, message })
        }

        const payload = {
            userId: user._id,
            doctorId: body?.doctorId,
            slotId: findAvailability._id,
        }

        const createSlot = await BookedSlot.create(payload)

        if (isEmpty(createSlot)) {
            console.log('createSlot: ', createSlot)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const updateAvailability = await DocAvailability.updateOne(
            { _id: findAvailability._id },
            { $set: { isLocked: true, lockedAt: null, bookedAt: moment().toDate() } },
        ).lean()

        if (updateAvailability.modifiedCount === 0) {
            await BookedSlot.deleteOne({ _id: createSlot._id })
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Slot booked successfully' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
