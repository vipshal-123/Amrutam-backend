import mongoose from 'mongoose'

const UserSchema = new mongoose.Schema({}, { timestamps: true })

const User = mongoose.model('users', UserSchema, 'users')
export default User
