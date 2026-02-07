import { Router } from "express";
import { registerUser } from "@/controller/auth.controller";

const router = Router();

router.route("/register").post(registerUser);

export default router;