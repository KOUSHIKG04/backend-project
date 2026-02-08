import type { Request, Response, NextFunction } from "express";
import { ZodError, type ZodSchema } from "zod";
import { ApiError } from "@/lib/apiResponses";

export const validate =
    (schema: ZodSchema) =>
        async (req: Request, res: Response, next: NextFunction) => {
            try {
                const { body, query, params } = req
                await schema.parseAsync({ body: body, query: query, params: params, });
                return next();
            } catch (error) {
                if (error instanceof ZodError) {
                    const errors = (error as any).errors.map((e: any) => ({
                        field: e.path.join("."),
                        message: e.message,
                    }));

                    // Respond with ApiError structure
                    const apiError = new ApiError(400, "Validation Error", errors);
                    res.status(apiError.statusCode).json(apiError);
                    return;
                }
                return next(error);
            }
        };
