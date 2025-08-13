import * as enums from '@/constants/enums'
import { User } from '@/models'
import isEmpty from 'is-empty'
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
            dbQuery = { ...dbQuery, _id: { $lt: decodeData._id } }
        }

        const aggregationQuery = [
            {
                $match: dbQuery,
            },
            {
                $limit: parseInt(query?.limit || 10),
            },
            {
                $sort: {
                    _id: -1,
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
