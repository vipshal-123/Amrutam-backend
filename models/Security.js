import mongoose from 'mongoose'
import * as enums from '@/constants/enums'

const SecuritySchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            required: true,
        },
        type: {
            type: String,
            enum: Object.values(enums.SECURITY_TYPES),
            default: null,
        },
        mode: {
            type: String,
            enum: Object.values(enums.SECURITY_MODES),
            default: null,
        },
        value: {
            type: String,
            default: '',
        },
        secret: {
            type: String,
            default: null,
        },
        expiresAt: {
            type: Date,
            default: null,
        },
        otpRequestedAt: {
            type: Date,
            default: null,
        },
        securityCount: {
            type: Number,
            default: 0,
        },
        tries: {
            type: Number,
            default: 0,
        },
    },
    { timestamps: true },
)

const Security = mongoose.model('security', SecuritySchema, 'security')
export default Security
