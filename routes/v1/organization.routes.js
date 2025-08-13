import express from 'express'
import * as controller from '@/controllers'
import { userAuthenticate as userAuth } from '@/security/passport'

const router = express.Router()

router.route('/doctors-list').get(userAuth, controller.v1.organization.doctorList)

export default router
