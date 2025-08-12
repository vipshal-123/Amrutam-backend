import mongoose from 'mongoose'
import * as enums from '@/constants/enums'

const OrganizationSchema = new mongoose.Schema(
    {
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'users',
            required: true,
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
        type: {
            type: String,
            enum: Object.values(enums.ORG_TYPES),
            required: true,
        },
        address: {
            type: String,
            trim: true,
            required: true,
        },
        city: {
            type: String,
            trim: true,
            required: true,
        },
        state: {
            type: String,
            trim: true,
            required: true,
        },
        country: {
            type: String,
            trim: true,
            required: true,
        },
        pincode: {
            type: String,
            trim: true,
            required: true,
        },
        contactPerson: {
            type: String,
            trim: true,
            required: true,
        },
        phone: {
            type: String,
            trim: true,
            required: true,
        },
        description: {
            type: String,
            trim: true,
            default: '',
        },
    },
    { timestamps: true },
)

const Organization = mongoose.model('organization', OrganizationSchema, 'organization')
export default Organization
