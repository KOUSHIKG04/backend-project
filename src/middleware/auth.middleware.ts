import { asyncHandler } from "@/lib/asyncHandler";
import type { Request, Response, NextFunction } from "express";
import { ApiError } from "@/lib/apiResponses";
import jwt from "jsonwebtoken";
import { prisma } from "@/db";



export const verifyJWT = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const token
        = req.cookies?.accessToken || req.headers.authorization?.split(" ")[1];

    if (!token) {
        throw new ApiError(401, "Unauthorized request");
    }

    try {
        const decoded
            = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET as string) as jwt.JwtPayload & { _id: number };

        const user = await prisma.user.findUnique({
            where: { id: decoded?._id },
            select: {
                id: true, email: true, username: true, fullname: true, createdAt: true
            }
        })

        if (!user) {
            throw new ApiError(401, "Invalid access token");
        }

        (req as any).user = user;
        next();

    } catch (error) {
        throw new ApiError(401, "Invalid or expired token");
    }
})

