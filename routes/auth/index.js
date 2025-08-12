import express from 'express'
import userRoutes from './user.routes'
import orgRoutes from './organization.routes'

const router = express.Router()

router.use('/user', userRoutes)
router.use('/organization', orgRoutes)

export default router
