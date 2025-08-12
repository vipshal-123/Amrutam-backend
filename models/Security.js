import mongoose from 'mongoose'

const SecuritySchema = new mongoose.Schema({}, { timestamps: true })

const Security = mongoose.model('security', SecuritySchema, 'security')
export default Security