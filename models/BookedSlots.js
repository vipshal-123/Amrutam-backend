import mongoose from 'mongoose'
import * as enums from '@/constants/enums'

const BookedSlotSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            required: true,
        },
        doctorId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            required: true,
        },
        slotId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'docAvailability',
            required: true,
        },
        status: {
            type: String,
            default: enums.BOOKING_STATUS.PENDING,
        },
    },
    { timestamps: true },
)

const BookedSlot = mongoose.model('bookedSlot', BookedSlotSchema, 'bookedSlot')
export default BookedSlot
