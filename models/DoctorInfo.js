import mongoose from 'mongoose'

const DoctorInfoSchema = new mongoose.Schema(
    {
        organizationId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'organization',
            required: true,
        },
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            required: true,
        },
        specialization: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'specialization',
            required: true,
        },
        experience: {
            type: Number,
            required: true,
        },
        availability: {
            type: [String],
            required: true,
        },
        contact: {
            type: String,
            trim: true,
            required: true,
        },
        bio: {
            type: String,
            trim: true,
            default: '',
        },
    },
    { timestamps: true },
)

const DoctorInfo = mongoose.model('doctorInfo', DoctorInfoSchema, 'doctorInfo')
export default DoctorInfo
