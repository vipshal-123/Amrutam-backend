import mongoose from 'mongoose'

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
    },
    { timestamps: true },
)

const BookedSlot = mongoose.model('bookedSlot', BookedSlotSchema, 'bookedSlot')
export default BookedSlot
