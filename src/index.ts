import 'dotenv/config'
import { connectDB } from '@/db';
import app from '@/app';

const port = process.env.PORT || 3000;

connectDB()
    .then(() => {
        app.listen(port, () => {
            console.log(`Server is running on http://localhost:${port}`);
        });
    })
    .catch((err) => {
        console.log("Database connection failed !!! ", err);
        throw err
    })
