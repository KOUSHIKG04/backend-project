import { Router } from "express";
import { userLogin, registerUser, userLogout, getCurrentUser, verifyEmail, resendEmailVerification, refreshAccessToken, forgotPassword, resetPassword, changeCurrentPassword } from "@/controller/auth.controller";
import { validate } from "@/middleware/validate";
import { registerUserSchema, loginUserSchema, forgotPasswordSchema, resetPasswordSchema, changePasswordSchema } from "@/validators/user.validator";
import { verifyJWT } from "@/middleware/auth.middleware";

const router = Router();

router.route("/register").post(validate(registerUserSchema), registerUser);
router.route("/login").post(validate(loginUserSchema), userLogin);
router.route("/current-user").get(verifyJWT, getCurrentUser);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);
router.route("/logout").post(verifyJWT, userLogout);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post(validate(forgotPasswordSchema), forgotPassword);
router.route("/reset-password/:resetToken").post(validate(resetPasswordSchema), resetPassword);
router.route("/change-password").post(verifyJWT, validate(changePasswordSchema), changeCurrentPassword);

export default router;