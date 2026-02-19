import { Router } from "express";
import { userLogin, registerUser, userLogout, getCurrentUser, verifyEmail, resendEmailVerification, refreshAccessToken } from "@/controller/auth.controller";
import { validate } from "@/middleware/validate";
import { registerUserSchema, loginUserSchema } from "@/validators/user.validator";
import { verifyJWT } from "@/middleware/auth.middleware";

const router = Router();

router.route("/register").post(validate(registerUserSchema), registerUser);
router.route("/login").post(validate(loginUserSchema), userLogin);
router.route("/current-user").get(verifyJWT, getCurrentUser);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);
router.route("/logout").post(verifyJWT, userLogout);
router.route("/refresh-token").post(refreshAccessToken);

export default router;