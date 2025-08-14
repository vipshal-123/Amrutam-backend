import mongoose from 'mongoose'

const DocAvailabilitySchema = new mongoose.Schema(
    {
        doctorId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            required: true,
        },
        title: {
            type: String,
            default: '',
        },
        date: {
            type: Date,
            required: true,
        },
        start: {
            type: Date,
            required: true,
        },
        end: {
            type: Date,
            required: true,
        },
        count: {
            type: Number,
            default: 1,
        },
        isLocked: {
            type: Boolean,
            default: false,
        },
        lockedAt: {
            type: Date,
            default: null,
        },
        bookedAt: {
            type: Date,
            default: null,
        },
    },
    { timestamps: true },
)

const DocAvailability = mongoose.model('docAvailability', DocAvailabilitySchema, 'docAvailability')
export default DocAvailability
