import Mailgen from "mailgen";
import SMTPTransport from "nodemailer/lib/smtp-transport"
import nodemailer from "nodemailer"
import type { Transporter } from "nodemailer"

//type correction - any
export const sendMail = async (options: any) => {

    const transporter: Transporter<SMTPTransport.SentMessageInfo> =
        nodemailer.createTransport({
            host: process.env.MAILTRAP_SMTP_HOST,
            port: Number(process.env.MAILTRAP_SMTP_PORT || 2525),
            auth: {
                user: process.env.MAILTRAP_SMTP_USER,
                pass: process.env.MAILTRAP_SMTP_PASS,
            },
        });

    try {

        if (!options.email || !options.subject) {
            throw new Error("Email and subject are required");
        }

        const mailGenerator = new Mailgen({
            theme: 'default',
            product: {
                name: 'TASK MANAGER',
                link: 'https://taskmanager.com'
            }
        })

        const emailTextual
            = mailGenerator.generatePlaintext(options.mailGenerator)
        const emailHTML
            = mailGenerator.generate(options.mailGenerator)


        const sendMail
            = await transporter.sendMail(
                {
                    from: '"Task Manager" <noreply@taskmanager.com>',
                    to: options.email,
                    subject: options.subject,
                    text: emailTextual,
                    html: emailHTML,
                })

        return sendMail
    } catch (error) {
        console.error(error)
        throw error
    }
}


export const emailVerification = (username: string, verificationUrl: string) => {
    return {
        body: {
            name: username,
            intro: `Welcome ${username} We\'re very excited to have you on board.`,
            action: {
                instructions: 'To get started with us!, please click here:',
                button: {
                    color: '#ffa011ff',
                    text: 'Verify your account',
                    link: verificationUrl
                }
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
}


export const forgotPassword = (username: string, resetPasswordUrl: string) => {
    return {
        body: {
            name: username,
            intro: `Hi ${username}, you requested a password reset.`,
            action: {
                instructions: 'Click the button below to reset your password:',
                button: {
                    color: '#ffa011',
                    text: 'Reset Password',
                    link: resetPasswordUrl
                }
            },
            outro: 'If you didn\'t request this, please ignore this email. Your password remains unchanged.'
        }
    }
}
