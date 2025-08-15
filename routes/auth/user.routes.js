import express from 'express'
import * as controller from '@/controllers'

const router = express.Router()

router.route('/signup').post(controller.auth.user.signupSendOtp)
router.route('/verify-otp').post(controller.auth.user.verifySignupOtp)
router.route('/create-password').post(controller.auth.user.createPassword)
router.route('/resend-otp').post(controller.auth.user.resendOtp)
router.route('/signin').post(controller.auth.user.signin)

router.route('/signin-with-google').post(controller.auth.user.signinWithGoogle)

export default router
