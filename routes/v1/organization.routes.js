import express from 'express'
import * as controller from '@/controllers'
import { userAuthenticate as userAuth } from '@/security/passport'

const router = express.Router()

router.route('/doctors-list').get(userAuth, controller.v1.organization.doctorList)
router
    .route('/doctor-availability')
    .post(userAuth, controller.v1.organization.createAvailability)
    .get(userAuth, controller.v1.organization.getAvailability)
    .put(userAuth, controller.v1.organization.updateAvailability)

export default router
