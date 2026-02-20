import { asyncHandler } from "@/lib/asyncHandler";
import type { Request, Response } from "express";
import { prisma } from "@/db"
import { ApiError, ApiResponse } from "@/lib/apiResponses";
import { generateAccessToken, generateRefreshToken, generateTemporaryToken, hashPassword, verifyPassword } from "@/lib/auth";
import { sendMail, emailVerification, forgotPasswordEmailVerification } from "@/lib/mail";
import crypto from "crypto"
import jwt from "jsonwebtoken";



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

    const verificationUrl = `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email/${unHashedToken}`;

    await sendMail({
        email:
            user?.email, subject: "Please Do Email Verification",
        mailGenerator: emailVerification(user.username, verificationUrl)
    })


    const { avatar, createdAt } = user

    const createdUser = { username, email, fullname, avatar, createdAt }

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


export const userLogin = asyncHandler(async (req: Request, res: Response) => {

    const { email, username, password } = req.body

    if (!username && !email) {
        throw new ApiError(400, "Username or Email is required")
    }

    const user = await prisma.user.findFirst({
        where: {
            OR: [
                username ? { username } : {}, email ? { email } : {}
            ].filter(obj => Object.keys(obj).length > 0)
        }
    })

    if (!user) {
        throw new ApiError(404, "User does not exist, Please Create account");
    }

    const isVerifiedPassword = await verifyPassword(password, user.password);

    if (!isVerifiedPassword) {
        throw new ApiError(401, "Invalid user credentials");
    }

    const {
        accessToken,
        refreshToken
    } = await generateTokens(user.id);

    const loggedInUser = await prisma.user.findUnique({
        where: { id: user.id },
        select: {
            id: true, email: true, username: true, fullname: true, createdAt: true
        }
    })

    const options = { httpOnly: true, secure: true }

    res.status(200)
        .cookie("accessToken", accessToken, options).cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                { user: loggedInUser, accessToken, refreshToken },
                "User logged In Successfully"
            )
        )
})


export const userLogout = asyncHandler(async (req: Request, res: Response) => {

    await prisma.user.update({
        where: {
            id: (req as any).user.id
        },
        data: {
            refreshToken: null
        }
    })

    const options = { httpOnly: true, secure: true }

    res.status(200)
        .clearCookie("accessToken", options).clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged Out Successfully"))
})


export const getCurrentUser = asyncHandler(async (req: Request, res: Response) => {
    res.status(200)
        .json(new ApiResponse(200,
            (req as any).user,
            "User fetched successfully")
        )
})


export const verifyEmail = asyncHandler(async (req: Request, res: Response) => {
    const { verificationToken } = req.params;

    if (!verificationToken) {
        throw new ApiError(400, "Email verification token is missing");
    }

    const hashedToken = crypto
        .createHash("SHA256")
        .update(verificationToken as string)
        .digest("hex");

    const user = await prisma.user.findFirst({
        where: {
            emailVerificationToken: hashedToken, emailVerificationExpiry: { gt: new Date() }
        }
    });

    if (!user) {
        throw new ApiError(400, "Token is invalid or expired");
    }

    await prisma.user.update({
        where: { id: user.id },
        data: {
            isEmailVerified: true, emailVerificationToken: null, emailVerificationExpiry: null
        }
    });

    res.status(200).json(
        new ApiResponse(200, {}, "Email verified successfully")
    );
});


export const resendEmailVerification = asyncHandler(async (req: Request, res: Response) => {

    const userId = (req as any).user?.id

    if (!userId) {
        throw new ApiError(401, "Unauthorized request");
    }

    const user = await prisma.user.findUnique({
        where: { id: userId }
    })

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.isEmailVerified) {
        throw new ApiError(400, "Email is already verified");
    }

    const { unHashedToken, hashedToken, tokenExpiry }
        = generateTemporaryToken()

    await prisma.user.update({
        where: { id: user.id },
        data: {
            emailVerificationToken: hashedToken, emailVerificationExpiry: new Date(tokenExpiry)
        }
    })

    const verificationUrl = `${req.protocol}://${req.get("host")}/api/v1/auth/verify-email/${unHashedToken}`;

    await sendMail({
        email: user?.email, subject: "Resend Email Verification",
        mailGenerator: emailVerification(user.username, verificationUrl)
    })

    res.status(200).json(
        new ApiResponse(200, {}, "Verification email resent successfully")
    )
})


export const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {

    const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized request");
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET as string
        ) as jwt.JwtPayload;

        const user = await prisma.user.findUnique({
            where: { id: decodedToken?._id }
        })

        if (!user) {
            throw new ApiError(401, "Invalid refresh token");
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used");
        }

        const { accessToken, refreshToken: newRefreshToken } = await generateTokens(user.id);

        const options = { httpOnly: true, secure: true }

        res.status(200)
            .cookie("accessToken", accessToken, options).cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            )
    } catch (error) {
        throw new ApiError(401, (error as Error)?.message || "Invalid refresh token");
    }
})


export const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
    const { email } = req.body

    const user = await prisma.user.findFirst({
        where: { email }
    })

    if (!user) {
        throw new ApiError(404, "User not found", [])
    }

    const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken()

    await prisma.user.update({
        where: { id: user.id },
        data: {
            forgotPasswordToken: hashedToken, forgotPasswordExpiry: new Date(tokenExpiry)
        }
    })

    const resetPasswordUrl = `${process.env.FORGOT_PASSWORD_RESET_URL}/${unHashedToken}`;

    await sendMail({
        email: user.email, subject: "Password Reset Request",
        mailGenerator:
            forgotPasswordEmailVerification(user.username, resetPasswordUrl)
    })

    res.status(200).json(
        new ApiResponse(200, {}, "Password reset email sent successfully")
    )
})


export const resetPassword = asyncHandler(async (req: Request, res: Response) => {

    const { resetToken } = req.params; const { newPassword } = req.body;

    if (!newPassword) {
        throw new ApiError(400, "New password is required");
    }

    const hashedToken = crypto
        .createHash("SHA256")
        .update(resetToken as string)
        .digest("hex");

    const user = await prisma.user.findFirst({
        where: {
            forgotPasswordToken: hashedToken, forgotPasswordExpiry: { gt: new Date() }
        }
    });

    if (!user) {
        throw new ApiError(400, "Token is invalid or expired");
    }

    const hashedPassword = await hashPassword(newPassword);

    await prisma.user.update({
        where: { id: user.id },
        data: {
            password: hashedPassword, forgotPasswordToken: null, forgotPasswordExpiry: null
        }
    });

    res.status(200).json(new ApiResponse(200, {}, "Password reset successfully"));
});

export const changeCurrentPassword = asyncHandler(async (req: Request, res: Response) => {
    
    const { oldPassword, newPassword } = req.body;

    const userId = (req as any).user?.id;

    const user = await prisma.user.findUnique({
        where: { id: userId }
    });

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    const isPasswordCorrect = await verifyPassword(oldPassword, user.password);

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password");
    }

    const hashedPassword = await hashPassword(newPassword);

    await prisma.user.update({
        where: { id: userId },
        data: {
            password: hashedPassword
        }
    });

    res.status(200).json(
        new ApiResponse(200, {}, "Password changed successfully")
    );
});