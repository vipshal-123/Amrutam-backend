import * as enums from '@/constants/enums'
import { DocAvailability, User } from '@/models'
import isEmpty from 'is-empty'
import moment from 'moment'
import mongoose from 'mongoose'

export const doctorList = async (req, res) => {
    try {
        const { user, query } = req
        console.log('user: ', user)

        if (user.role !== enums.ROLES.ORG_ADMIN) {
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        let dbQuery = {
            organizationId: new mongoose.Types.ObjectId(user.organizationId),
            $expr: { $eq: ['$role', enums.ROLES.DOCTOR] },
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
                },
            },
        ]

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

export const createAvailability = async (req, res) => {
    try {
        const { user, body } = req

        if (user.role !== enums.ROLES.DOCTOR) {
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        const events = body?.event

        if (!Array.isArray(events)) {
            return res.status(400).json({ success: false, message: 'Invalid payload' })
        }

        if (isEmpty(events)) {
            return res.status(400).json({ success: false, message: 'Event is required' })
        }

        const payload = []

        for (const event of events) {
            if (moment(event?.start).isBefore(moment().toDate())) {
                return res.status(400).json({ success: false, message: 'Completed time cannot be selected' })
            }

            payload.push({
                doctorId: user._id,
                title: event?.title,
                date: moment(body?.date).toDate(),
                // count: event?.patientCount || 1,
                start: moment(event?.start).toDate(),
                end: moment(event?.end).toDate(),
            })
        }

        const createData = await DocAvailability.insertMany(payload)

        if (isEmpty(createData)) {
            console.log('createData: ', createData)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Availability added successfully' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const getAvailability = async (req, res) => {
    try {
        const { user } = req
        console.log('user: ', user)

        const aggregationQuery = [
            {
                $match: {
                    doctorId: new mongoose.Types.ObjectId(user._id),
                    $expr: {
                        $gte: [{ $month: '$date' }, { $month: '$$NOW' }],
                    },
                },
            },
            {
                $group: {
                    _id: {
                        $dateToString: {
                            format: '%Y-%m-%d',
                            date: '$date',
                        },
                    },
                    appointments: {
                        $push: {
                            _id: '$_id',
                            start: '$start',
                            end: '$end',
                            // patientCount: '$count',
                        },
                    },
                },
            },
        ]

        const availabilityData = await DocAvailability.aggregate(aggregationQuery)

        if (isEmpty(availabilityData)) {
            return res.status(200).json({ success: true, data: [] })
        }

        return res.status(200).json({ success: true, data: availabilityData })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}

export const updateAvailability = async (req, res) => {
    try {
        const { user, body } = req

        if (user.role !== enums.ROLES.DOCTOR) {
            return res.status(403).json({ success: false, message: 'Access denied' })
        }

        const events = body?.event

        if (isEmpty(events)) {
            await DocAvailability.deleteMany({
                doctorId: user._id,
                $expr: {
                    $eq: [
                        {
                            $dateToString: { format: '%Y-%m-%d', date: '$date' },
                        },
                        moment(date).format('YYYY-MM-DD'),
                    ],
                },
            })

            return res.status(200).json({ success: true, message: 'Availability updated successfully' })
        }

        const date = moment(body?.date).toDate()

        for (const event of events) {
            if (moment(event?.start).isBefore(moment())) {
                return res.status(400).json({
                    success: false,
                    message: 'Completed time cannot be selected',
                })
            }
        }

        const deleteEvent = await DocAvailability.deleteMany({
            doctorId: user._id,
            $expr: {
                $eq: [
                    {
                        $dateToString: { format: '%Y-%m-%d', date: '$date' },
                    },
                    moment(date).format('YYYY-MM-DD'),
                ],
            },
        })

        console.log('deleteEvent: ', deleteEvent)

        const payload = events.map((event) => ({
            doctorId: user._id,
            title: event?.title || 'Available',
            date: date,
            count: event?.patientCount || 1,
            start: moment(event?.start).toDate(),
            end: moment(event?.end).toDate(),
        }))

        const updatedData = await DocAvailability.insertMany(payload)

        if (isEmpty(updatedData)) {
            console.log('updatedData: ', updatedData)
            return res.status(500).json({ success: false, message: 'Something went wrong' })
        }

        return res.status(200).json({ success: true, message: 'Availability updated successfully' })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
