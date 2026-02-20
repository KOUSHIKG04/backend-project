import { z } from "zod";

export const registerUserSchema = z.object({
    body: z.object({
        email: z.email({ message: "Invalid email address" }),
        username: z.string().trim().toLowerCase().min(3, { message: "Username must be at least 3 characters long" }),
        fullname: z.string().trim().min(1, { message: "Fullname is required" }),
        password: z.string().min(6, { message: "Password must be at least 6 characters long" }),
    }),
});

export type RegisterUserInput = z.infer<typeof registerUserSchema>["body"];

/* export const loginUserSchema = z.object({
    body: z.object({
        email: z.string().email({ message: "Invalid email address" }).optional(),
        username: z.string().trim().toLowerCase().optional(),
        password: z.string().min(6, { message: "Password must be at least 6 characters long" }),
    }).refine((data) => data.email || data.username, {
        message: "Either username or email is required",
        path: ["email"],
    }),
}); */

export const loginUserSchema = z.object({
    body: z.object({
        email: z.email({ message: "Invalid email address" }).optional(),
        username: z.string().trim().min(1, "Username is required").optional(),
        password: z.string().min(6, { message: "Password must be at least 6 characters long" }),
    }).superRefine((data, ctx) => {
        if (!data.email && !data.username) {
            ctx.addIssue({
                code: "custom",
                message: "Either username or email is required",
                path: ["email"],
            });
            ctx.addIssue({
                code: "custom",
                message: "Either username or email is required",
                path: ["username"],
            });
        }
    }),
});

export type LoginUserInput = z.infer<typeof loginUserSchema>["body"];


export const forgotPasswordSchema = z.object({
    body: z.object({
        email: z.email({ message: "Invalid email address" }),
    }),
});

export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>["body"];

export const resetPasswordSchema = z.object({
    body: z.object({
        newPassword: z.string().min(6, { message: "Password must be at least 6 characters long" }),
    }),
});

export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>["body"];

export const changePasswordSchema = z.object({
    body: z.object({
        oldPassword: z.string().min(1, { message: "Old password is required" }),
        newPassword: z.string().min(6, { message: "New password must be at least 6 characters long" }),
    }),
});

export type ChangePasswordInput = z.infer<typeof changePasswordSchema>["body"];
