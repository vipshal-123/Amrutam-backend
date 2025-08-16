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

router.route('/booking-release-lock').post(userAuth, controller.v1.user.releaseLock)

router.route('/booking').get(userAuth, controller.v1.user.bookings)
router.route('/booking-reschedule').post(userAuth, controller.v1.user.rescheduleSlot)
router.route('/booking-cancel').post(userAuth, controller.v1.user.cancelSlot)

router.route('/doc-specialization').get(userAuth, controller.v1.user.getSpecialization)

router.route('/patient-list').get(userAuth, controller.v1.user.patientList)

export default router
