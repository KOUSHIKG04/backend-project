import { Router } from "express";
import { registerUser } from "@/controller/auth.controller";
import { validate } from "@/middleware/validate";
import { registerUserSchema } from "@/validators/user.validator";

const router = Router();

router.route("/register").post(validate(registerUserSchema), registerUser);

export default router;