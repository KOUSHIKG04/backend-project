import express, { urlencoded } from 'express';
import cors from "cors";

const application = express();

application.use(cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
}))

application.use(express.json({
    limit: "16kb"
}))
application.use(urlencoded({
    limit: "16kb",
    extended: true
}))
// application.use(express.static("public"))

application.get('/', (req, res) => {
    res.send('Hello World with Bun and Express!!')
});




import healthCheckRouter from "@/routes/healthCheck.route";
application.use("/api/v1/health-check", healthCheckRouter);

export default application