import mongoose from 'mongoose'
import * as enums from '@/constants/enums'

const UserSchema = new mongoose.Schema(
    {
        organizationId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'organization',
            default: null,
        },
        addedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            default: null,
        },
        name: {
            type: String,
            trim: true,
            required: true,
        },
        email: {
            type: String,
            trim: true,
            unique: true,
            required: true,
        },
        password: {
            type: String,
            trim: true,
            default: '',
        },
        role: {
            type: String,
            enum: enums.ROLES,
            required: true,
        },
        isEmailVerified: {
            type: Boolean,
            default: false,
        },
        status: {
            type: String,
            enum: Object.values(enums.STATUS),
            default: enums.STATUS.PENDING,
        },
    },
    { timestamps: true },
)

const User = mongoose.model('users', UserSchema, 'users')
export default User
