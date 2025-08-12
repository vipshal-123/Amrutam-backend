import nodemailer from 'nodemailer'
import config from '@/config'
import * as enums from '@/constants/enums'
import isEmpty from 'is-empty'
import { EmailTemplates } from '@/models'

// If we use sendinblue / brevo / sendgrid - use its custom transport with nodemailer transport
const sendEmail = async (toEmail, content, bcc = null) => {
    try {
        const { subject, template } = content
        const transport = nodemailer.createTransport({
            host: config.SMTP_HOST,
            port: config.SMTP_PORT,
            secure: config.SMTP_SECURE,
            auth: {
                user: config.SMTP_USER,
                pass: config.SMTP_PASS,
            },
        })

        const mailSentInformation = await transport.sendMail({
            from: config.SMTP_MAIL,
            to: toEmail,
            bcc: bcc,
            subject,
            html: template,
        })

        console.log('Mail sent info: ', mailSentInformation.accepted, mailSentInformation.messageId)
        return true
    } catch (error) {
        console.log('Error in sending email', error)
        return false
    }
}

export const sendEmailViaTemplate = async ({ identifier, to, content, bcc }) => {
    try {
        const template = await EmailTemplates.findOne({ identifier })

        if (isEmpty(template)) {
            console.log('No email template found for', identifier)
            return false
        }

        if (template.status === 'INACTIVE') {
            console.log(`${identifier} template is currently inactive`)
        }

        const mailContent = { subject: '', template: '' }

        mailContent['subject'] = template.subject
        mailContent['template'] = template.content

        switch (identifier) {
            case enums.EMAIL_CATEGORIES.OTP_TEMPLATE:
                mailContent['template'] = mailContent['template'].replaceAll('##OTP##', content.otp)
                break
            default:
                break
        }

        return await sendEmail(to, mailContent, bcc)
    } catch (error) {
        console.log('sendEmailViaTemplate', error)
        return false
    }
}
