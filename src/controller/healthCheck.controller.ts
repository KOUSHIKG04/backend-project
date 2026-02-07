import { ApiResponse } from "@/lib/apiResponses";
import type { Request, Response } from "express";
import { asyncHandler } from "@/lib/asyncHandler";


const healthCheck = asyncHandler(async (req: Request, res: Response) => {
    return res.status(200).json(
        new ApiResponse(200, "", "Health check passed")
    )
})

export { healthCheck }