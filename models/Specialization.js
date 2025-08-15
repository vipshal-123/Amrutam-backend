import mongoose from 'mongoose'
import * as enums from '@/constants/enums'

const SpecializationSchema = new mongoose.Schema(
    {
        title: {
            type: String,
            trim: true,
            required: true,
        },
        status: {
            type: String,
            default: enums.STATUS.ACTIVE,
        },
    },
    { timestamps: true },
)

const Specialization = mongoose.model('specialization', SpecializationSchema, 'specialization')
export default Specialization
