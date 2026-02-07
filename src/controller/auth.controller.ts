import { asyncHandler } from "@/lib/asyncHandler";
import type { Request, Response } from "express";
import { prisma } from "@/db"
import { ApiError, ApiResponse } from "@/lib/apiResponses";
import { generateAccessToken, generateRefreshToken, generateTemporaryToken, hashPassword } from "@/lib/auth";
import { sendMail, emailVerification } from "@/lib/mail";

const generateTokens = async (userId: number) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: userId }
        })

        if (!user) {
            throw new ApiError(404, "User not found")
        }

        const { id, username, email } = user

        const accessToken
            = generateAccessToken(id, username, email)
        const refreshToken = generateRefreshToken(id)

        user.refreshToken = refreshToken
        await prisma.user.update({
            where: { id: id },
            data: {
                refreshToken: refreshToken
            }
        })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating tokens")
    }
}

export const registerUser = asyncHandler(async (req: Request, res: Response) => {

    const { username, email, password, role, fullname } = req.body

    const existingUser = await prisma.user.findFirst({
        where: { OR: [{ username }, { email }] }
    })

    if (existingUser) {
        throw new ApiError(409, "User with email or username already exists", [])
    }


    const hashedPassword
        = await hashPassword(password)

    const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken()

    const user = await prisma.user.create({
        data: {
            username,
            fullname,
            email,
            password: hashedPassword,
            // isEmailVerified: false
            emailVerificationToken: hashedToken,
            emailVerificationExpiry: new Date(tokenExpiry),
        }
    })

    await sendMail({
        email: user?.email, subject: "Please Do Email Verification",
        mailGenerator:
            emailVerification(
                user.username,
                `${req.protocol}://${req.get("host")}/api/v1/users/${unHashedToken}`
            )
    })


    const { avatar, createdAt } = user
    const createdUser = {
        username: username,
        email: email,
        fullname: fullname,
        avatar: avatar,
        createdAt: createdAt
    }
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    res.status(201).json(
        new ApiResponse(201,
            { user: createdUser },
            `User registered successfully and verification mail is sent to your entered email`
        )
    )

});