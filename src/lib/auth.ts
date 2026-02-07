import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";
import crypto from "crypto"


export const hashPassword = async (password: string)
    : Promise<string> => {
    return await bcrypt.hash(password, 13)
}

export const verifyPassword = async (password: string, hashed: string)
    : Promise<boolean> => {
    return await bcrypt.compare(password, hashed)
}

export const generateAccessToken = (
    userId: number,
    username: string,
    email: string
): string => {

    const options: jwt.SignOptions = {
        expiresIn:
            (process.env.ACCESS_TOKEN_EXPIRES || '15m') as jwt.SignOptions['expiresIn']
    }

    return jwt.sign(
        { _id: userId, username, email },
        process.env.ACCESS_TOKEN_SECRET!,
        options
    )
}

export const generateRefreshToken = (userId: number): string => {
    const options: jwt.SignOptions = {
        expiresIn:
            (process.env.REFRESH_TOKEN_EXPIRES || '7d') as jwt.SignOptions['expiresIn']
    }

    return jwt.sign(
        { _id: userId },
        process.env.REFRESH_TOKEN_SECRET!,
        options
    )
}


export const generateTemporaryToken = () => {
    const unHashedToken
        = crypto.randomBytes(20).toString("hex")

    const hashedToken = crypto
        .createHash("SHA256")
        .update(unHashedToken)
        .digest("hex")

    const tokenExpiry = Date.now() + (20 * 60 * 1000)

    return { unHashedToken, hashedToken, tokenExpiry }
}

