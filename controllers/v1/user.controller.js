import isEmpty from 'is-empty'
import * as enums from '@/constants/enums'
import mongoose from 'mongoose'
import { BookedSlot, DocAvailability, Security, Specialization, User } from '@/models'
import { sendOtp, verifyOtp } from '@/security/auth.security'
import { decryptString } from '@/security/crypto'
import moment from 'moment'

export const userInfo = async (req, res) => {
    try {
        const { user } = req

        if (isEmpty(user)) {
            return res.status(200).json({ success: true, data: {} })
        }

        const findUser = await User.findById(user._id).select('_id email').lean()

        const formattedData = {
            _id: user._id,
            organizationId: user?.organizationId || null,
            role: user.role,
            email: findUser.email,
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
                    pipeline: [
                        {
                            $lookup: {
                                from: 'specialization',
                                localField: 'specialization',
                                foreignField: '_id',
                                as: 'specialization',
                            },
                        },
                        {
                            $unwind: {
                                path: '$specialization',
                                preserveNullAndEmptyArrays: true,
                            },
                        },
                    ],
                    as: 'doctorInfo',
                },
            },
            {
                $unwind: {
                    path: '$doctorInfo',
                    preserveNullAndEmptyArrays: true,
                },
            },
        ]

        if (!isEmpty(query?.specFilter)) {
            aggregationQuery.push({
                $match: {
                    'doctorInfo.specialization._id': new mongoose.Types.ObjectId(query?.specFilter),
                },
            })
        }

        if (!isEmpty(query?.type)) {
            aggregationQuery.push({
                $match: {
                    'doctorInfo.availability': query?.type,
                },
            })
        }

        aggregationQuery.push({
            $project: {
                _id: 1,
                name: 1,
                email: 1,
                specialization: '$doctorInfo.specialization.title',
                experience: '$doctorInfo.experience',
                mode: '$doctorInfo.availability',
                bio: '$doctorInfo.bio',
                status: 1,
                isEmailVerified: 1,
            },
        })

        const findDoctors = await User.aggregate(aggregationQuery)

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
        const { user, params, query } = req
        console.log('user: ', user)

        if (user.role !== enums.ROLES.USER) {
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        const findIds = await BookedSlot.find({ userId: user._id }).distinct('slotId').lean()
        console.log('findIds: ', findIds)

        let rescheduleFilter = {}

        if (!isEmpty(query?.rescheduleDate)) {
            rescheduleFilter = {
                $eq: ['$start', new Date(query.rescheduleDate)],
            }
        }

        console.log('rescheduleFilter: ', rescheduleFilter)

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
                    pipeline: [
                        {
                            $lookup: {
                                from: 'specialization',
                                localField: 'specialization',
                                foreignField: '_id',
                                as: 'specialization',
                            },
                        },
                        {
                            $unwind: {
                                path: '$specialization',
                                preserveNullAndEmptyArrays: true,
                            },
                        },
                    ],
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
                    pipeline: [
                        {
                            $match: {
                                $expr: {
                                    $or: [
                                        {
                                            $and: [
                                                {
                                                    $gt: [
                                                        {
                                                            $dateToString: {
                                                                format: '%Y-%m-%d',
                                                                date: '$date',
                                                            },
                                                        },
                                                        moment().format('YYYY-MM-DD'),
                                                    ],
                                                },
                                                {
                                                    $in: ['$_id', findIds],
                                                },
                                                { $eq: ['$isLocked', true] },
                                                rescheduleFilter,
                                            ],
                                        },
                                        {
                                            $and: [
                                                {
                                                    $gt: [
                                                        {
                                                            $dateToString: {
                                                                format: '%Y-%m-%d',
                                                                date: '$date',
                                                            },
                                                        },
                                                        moment().format('YYYY-MM-DD'),
                                                    ],
                                                },
                                                {
                                                    $not: [
                                                        {
                                                            $in: ['$_id', findIds],
                                                        },
                                                    ],
                                                },
                                                { $eq: ['$isLocked', false] },
                                            ],
                                        },
                                    ],
                                },
                            },
                        },
                    ],
                    as: 'docAvailability',
                },
            },
            {
                $project: {
                    _id: 1,
                    name: 1,
                    email: 1,
                    specialization: '$doctorInfo.specialization.title',
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
                    pipeline: [
                        {
                            $lookup: {
                                from: 'specialization',
                                localField: 'specialization',
                                foreignField: '_id',
                                as: 'specialization',
                            },
                        },
                        {
                            $unwind: {
                                path: '$specialization',
                                preserveNullAndEmptyArrays: true,
                            },
                        },
                    ],
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
                    specialization: '$doctorInfo.specialization.title',
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

        const findBookedSlot = await BookedSlot.findOne({ userId: user._id, slotId: body?.availabilityId }).select('_id').lean()

        if (!isEmpty(findBookedSlot)) {
            return res.status(400).json({ success: false, message: 'Slot already cancelled, select another slot' })
        }

        const findAvailability = await DocAvailability.findById(body?.availabilityId).select('_id lockedAt isLocked').lean()

        if (isEmpty(findAvailability)) {
            console.log('findAvailability: ', findAvailability)
            return res.status(400).json({ success: false, message: 'Invalid availability id' })
        }

        if (findAvailability.isLocked) {
            return res.status(400).json({ success: false, message: 'Slot was already locked' })
        }

        if (!isEmpty(findAvailability?.lockedAt) && moment().diff(moment(findAvailability.lockedAt), 'minutes') < 10) {
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

        return res.status(200).json({ success: true, message: 'Otp send to your mail', token, _id: findAvailability._id })
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
        console.log('decryptToken: ', decryptToken)

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
            console.log('status: ', status)
            return res.status(400).json({ success: false, message })
        }

        const payload = {
            userId: user._id,
            doctorId: body?.doctorId,
            slotId: findAvailability._id,
            status: enums.BOOKING_STATUS.BOOKED,
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

export const releaseLock = async (req, res) => {
    try {
        const { body } = req

        if (isEmpty(body?.token)) {
            return res.status(400).json({ success: false, message: 'Token is required' })
        }

        const decryptToken = JSON.parse(decryptString(body?.token))

        const findAvailability = await DocAvailability.findById(body?.availabilityId).select('_id').lean()

        if (isEmpty(findAvailability)) {
            console.log('findAvailability: ', findAvailability)
            return res.status(400).json({ success: false, message: 'Invalid availability id' })
        }

        const updateData = {
            value: '',
            expiresAt: null,
            secret: null,
            tries: 0,
            securityCount: 0,
            otpRequestedAt: null,
        }

        const updateSecurity = await Security.updateOne(
            { userId: decryptToken._id, type: enums.SECURITY_TYPES.ACTIVATION_MAIL },
            { $set: updateData },
        ).lean()

        if (updateSecurity.modifiedCount === 0) {
            console.log('updateSecurity: ', updateSecurity)
            return { status: false, message: 'Something went wrong' }
        }

        const updateAvailability = await DocAvailability.updateOne({ _id: findAvailability._id }, { $set: { lockedAt: null } }).lean()

        if (updateAvailability.modifiedCount === 0) {
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Lock released successfully' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const bookings = async (req, res) => {
    try {
        const { user, query } = req

        let dbQuery = {
            userId: new mongoose.Types.ObjectId(user._id),
        }

        if (!isEmpty(query?.next)) {
            const decodeData = JSON.parse(Buffer.from(query?.next, 'base64').toString('utf-8'))
            dbQuery = { ...dbQuery, _id: { $lt: new mongoose.Types.ObjectId(decodeData._id) } }
        }

        if (!isEmpty(query?.type) && query?.type === 'book') {
            dbQuery = { ...dbQuery, status: enums.BOOKING_STATUS.BOOKED }
        }

        if (!isEmpty(query?.type) && query?.type === 'cancel') {
            dbQuery = { ...dbQuery, status: enums.BOOKING_STATUS.CANCELLED }
        }

        let bookingsDate = {
            $gte: [
                {
                    $dateToString: {
                        format: '%Y-%m-%d',
                        date: '$docAvailability.date',
                    },
                },
                moment().format('YYYY-MM-DD'),
            ],
        }

        if (!isEmpty(query?.timeline) && query?.timeline === 'past') {
            bookingsDate = {
                $lt: [
                    {
                        $dateToString: {
                            format: '%Y-%m-%d',
                            date: '$docAvailability.date',
                        },
                    },
                    moment().format('YYYY-MM-DD'),
                ],
            }
        }

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
                    from: 'docAvailability',
                    localField: 'slotId',
                    foreignField: '_id',
                    as: 'docAvailability',
                },
            },
            {
                $unwind: {
                    path: '$docAvailability',
                    preserveNullAndEmptyArrays: true,
                },
            },
            {
                $match: {
                    $expr: bookingsDate,
                },
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'doctorId',
                    foreignField: '_id',
                    pipeline: [
                        {
                            $lookup: {
                                from: 'doctorInfo',
                                localField: '_id',
                                foreignField: 'userId',
                                pipeline: [
                                    {
                                        $lookup: {
                                            from: 'specialization',
                                            localField: 'specialization',
                                            foreignField: '_id',
                                            as: 'specialization',
                                        },
                                    },
                                    {
                                        $unwind: {
                                            path: '$specialization',
                                            preserveNullAndEmptyArrays: true,
                                        },
                                    },
                                ],
                                as: 'doctorInfo',
                            },
                        },
                        {
                            $unwind: {
                                path: '$doctorInfo',
                                preserveNullAndEmptyArrays: true,
                            },
                        },
                    ],
                    as: 'doctor',
                },
            },
            {
                $unwind: {
                    path: '$doctor',
                    preserveNullAndEmptyArrays: true,
                },
            },
            {
                $project: {
                    _id: 1,
                    doctorId: 1,
                    slotId: 1,
                    name: '$doctor.name',
                    specialization: '$doctor.doctorInfo.specialization.title',
                    date: '$docAvailability.date',
                    start: '$docAvailability.start',
                    end: '$docAvailability.end',
                    status: 1,
                },
            },
        ]

        const bookingData = await BookedSlot.aggregate(aggregationQuery)

        if (isEmpty(bookingData)) {
            return res.status(200).json({ success: true, data: [], next: '' })
        }

        const lastData = bookingData[bookingData.length - 1]._id
        const encodeData = Buffer.from(JSON.stringify({ _id: lastData }), 'utf-8').toString('base64')

        return res.status(200).json({ success: true, data: bookingData, next: encodeData })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const rescheduleSlot = async (req, res) => {
    try {
        const { body } = req

        const findSlot = await BookedSlot.findById(body?.slotId).lean()

        if (isEmpty(findSlot)) {
            return res.status(404).json({ success: false, message: 'Booked slot not found' })
        }

        const docAvailability = await DocAvailability.findById(findSlot.slotId).select('_id bookedAt').lean()

        if (isEmpty(docAvailability)) {
            return res.status(404).json({ success: false, message: 'Doctor availability not found' })
        }

        const updateAvailability = await DocAvailability.updateOne(
            { _id: findSlot.slotId },
            { $set: { isLocked: false, bookedAt: null, lockedAt: null } },
        ).lean()

        if (updateAvailability.modifiedCount === 0) {
            console.log('updateAvailability: ', updateAvailability)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const reschedule = await BookedSlot.updateOne({ _id: findSlot._id }, { $set: { slotId: body.newSlot } }).lean()

        if (reschedule.modifiedCount === 0) {
            await DocAvailability.updateOne(
                { _id: findSlot.slotId },
                { $set: { isLocked: docAvailability?.isLocked, bookedAt: docAvailability?.bookedAt, lockedAt: docAvailability?.lockedAt } },
            ).lean()
            console.log('reschedule: ', reschedule)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const updateNewAvailability = await DocAvailability.updateOne(
            { _id: body.newSlot },
            { $set: { isLocked: true, bookedAt: moment().toDate(), lockedAt: null } },
        ).lean()

        if (updateNewAvailability.modifiedCount === 0) {
            console.log('updateNewAvailability: ', updateNewAvailability)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Slot rescheduled successfully' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const cancelSlot = async (req, res) => {
    try {
        const { body } = req

        const findSlot = await BookedSlot.findById(body?.slotId).lean()

        if (isEmpty(findSlot)) {
            return res.status(404).json({ success: false, message: 'Booked slot not found' })
        }

        const docAvailability = await DocAvailability.findById(findSlot.slotId).select('_id bookedAt').lean()

        if (isEmpty(docAvailability)) {
            return res.status(404).json({ success: false, message: 'Doctor availability not found' })
        }

        const updateAvailability = await DocAvailability.updateOne(
            { _id: findSlot.slotId },
            { $set: { isLocked: false, bookedAt: null, lockedAt: null } },
        ).lean()

        if (updateAvailability.modifiedCount === 0) {
            console.log('updateAvailability: ', updateAvailability)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        const reschedule = await BookedSlot.updateOne({ _id: findSlot._id }, { $set: { status: enums.BOOKING_STATUS.CANCELLED } }).lean()

        if (reschedule.modifiedCount === 0) {
            await DocAvailability.updateOne(
                { _id: findSlot.slotId },
                { $set: { isLocked: docAvailability?.isLocked, bookedAt: docAvailability?.bookedAt, lockedAt: docAvailability?.lockedAt } },
            ).lean()
            console.log('reschedule: ', reschedule)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Slot cancelled successfully' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const getSpecialization = async (req, res) => {
    try {
        const { query } = req

        let dbQuery = { status: enums.STATUS.ACTIVE }

        if (!isEmpty(query?.next)) {
            const decodeData = JSON.parse(Buffer.from(query?.next, 'base64').toString('utf-8'))
            dbQuery = { ...dbQuery, _id: { $lt: decodeData._id } }
        }

        const findData = await Specialization.find(dbQuery)
            .sort({ _id: -1 })
            .limit(parseInt(query?.limit || 10))
            .lean()

        if (isEmpty(findData)) {
            return res.status(200).json({ success: true, data: [], next: '' })
        }

        const lastData = findData[findData.length - 1]._id
        const encodeData = Buffer.from(JSON.stringify({ _id: lastData }), 'utf-8').toString('base64')

        return res.status(200).json({ success: true, data: findData, next: encodeData })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const patientList = async (req, res) => {
    try {
        const { user, query } = req
        let dbQuery = { doctorId: new mongoose.Types.ObjectId(user._id), status: enums.BOOKING_STATUS.BOOKED }

        if (!isEmpty(query?.next)) {
            const decodeData = JSON.parse(Buffer.from(query.next, 'base64').toString('utf-8'))
            dbQuery = { ...dbQuery, _id: { $lt: decodeData._id } }
        }

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
                $limit: parseInt(query?.next) || 10,
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'user',
                },
            },
            {
                $unwind: {
                    path: '$user',
                    preserveNullAndEmptyArrays: true,
                },
            },
            {
                $lookup: {
                    from: 'docAvailability',
                    localField: 'slotId',
                    foreignField: '_id',
                    as: 'docAvailability',
                },
            },
            {
                $unwind: {
                    path: '$docAvailability',
                    preserveNullAndEmptyArrays: true,
                },
            },
            {
                $project: {
                    _id: 1,
                    status: 1,
                    createdAt: 1,
                    updatedAt: 1,
                    userId: 1,
                    doctorId: 1,
                    name: '$user.name',
                    email: '$user.email',
                    date: '$docAvailability.date',
                    start: '$docAvailability.start',
                    end: '$docAvailability.end',
                },
            },
        ]

        const patientData = await BookedSlot.aggregate(aggregationQuery)

        if (isEmpty(patientData)) {
            return res.status(200).json({ success: true, data: [], next: '' })
        }

        const lastData = patientData[patientData.length - 1]._id
        const encodeData = Buffer.from(JSON.stringify({ _id: lastData }), 'utf-8').toString('base64')

        return res.status(200).json({ success: true, data: patientData, next: encodeData })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
