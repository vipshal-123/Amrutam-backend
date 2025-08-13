import express from 'express'
import * as controller from '@/controllers'
import { userAuthenticate as userAuth } from '@/security/passport'

const router = express.Router()

router.route('/send-otp').post(controller.auth.organization.createOrgSendOtp)
router.route('/verify-otp').post(controller.auth.organization.createOrgVerifyOtp)
router.route('/resend-otp').post(controller.auth.organization.resendOtp)

router.route('/add-doctor').post(userAuth, controller.auth.organization.addDoctors)
router.route('/doctor-create-password').post(controller.auth.organization.verifyDocMail)
router.route('/resend-doc-mail').post(userAuth, controller.auth.organization.resendAddDoctorsMail)

router.route('/doctor-signin').post(controller.auth.organization.doctorSignin)

router.route('/admin-signin-send-otp').post(controller.auth.organization.orgAdminLoginSendOtp)
router.route('/verify-signin-otp').post(controller.auth.organization.orgAdminVerifyOtp)

export default router
