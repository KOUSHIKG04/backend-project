import { PrismaClient } from "@prisma/client"
import { Pool } from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'

const connectionString = `${process.env.DATABASE_URL}`

/**
 * Pool: Reuses DB connections
 * Why It's Better: Prevents connection exhaustion (100s of React components = 100s of connections)
 */
const pool = new Pool({ connectionString })

/**
 * PrismaPg: Adapts pool to Prisma  
 * Why It's Better: Prisma doesn't create new connections per query
 */
const adapter = new PrismaPg(pool)

/**
 * adapter: Tells Prisma "use my pool"
 * Why It's Better: Serverless/Edge ready (Neon, Vercel, etc.)
 */
const prisma = new PrismaClient({
    adapter,
    log: ['warn', 'error'],
})

/**
 * connectDB(): Explicit startup test  
 * Why It's Better: Catches DB issues before your app crashes
 */
const connectDB = async () => {
    try {
        console.log("Connecting to database...")
        await prisma.$connect()
        console.log("Connection successfull..!")
    } catch (error) {
        console.log("Database connection error ", error)
        process.exit(1)
    }
}

export { prisma, connectDB }



/**
* PrismaPg: Bridges pool ↔ Prisma → efficient query handling
* Pool: Explains connection reuse → no connection exhaustion
* adapter: Configures Prisma to use pooled connections → production - ready
* connectDB: Startup validation → prevents runtime crashes

*/




// Usage in Your Electron / React App
// typescript
// // main process (preload via contextBridge)
// import { prisma, connectDB } from './db'
// await connectDB()

// // In React components (via IPC)
// const users = await prisma.user.findMany()