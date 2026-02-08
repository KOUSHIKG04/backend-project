import { z } from "zod";

export const registerUserSchema = z.object({
    body: z.object({
        email: z.email({ message: "Invalid email address" }),
        username: z.string().min(3, { message: "Username must be at least 3 characters long" }),
        password: z.string().min(6, { message: "Password must be at least 6 characters long" }),
    }),
});

export type RegisterUserInput = z.infer<typeof registerUserSchema>["body"];
