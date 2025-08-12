import express from 'express'
import * as controller from '@/controllers'

const router = express.Router()

router.route('/send-otp').post(controller.auth.organization.createOrgSendOtp)
router.route('/verify-otp').post(controller.auth.organization.createOrgVerifyOtp)
router.route('/resend-otp').post(controller.auth.organization.resendOtp)

export default router
