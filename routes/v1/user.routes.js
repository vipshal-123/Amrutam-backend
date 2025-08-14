import express from 'express'
import * as controller from '@/controllers'
import { userAuthenticate as userAuth } from '@/security/passport'

const router = express.Router()

router.route('/user-info').get(userAuth, controller.v1.user.userInfo)
router.route('/doctors-list').get(userAuth, controller.v1.user.doctorList)
router.route('/doctor/:id').get(userAuth, controller.v1.user.singleDoctor)

router.route('/booking/:id').get(userAuth, controller.v1.user.getBookingSlots)

router.route('/booking-send-otp').post(userAuth, controller.v1.user.slotBookingSendOtp)
router.route('/booking-verify-otp').post(userAuth, controller.v1.user.slotBookingVerifyOtp)

export default router
