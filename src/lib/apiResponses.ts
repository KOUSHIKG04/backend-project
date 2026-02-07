
// class ApiResponse {
//     constructor(
//         public statusCode: number,
//         public data: any,
//         public message: string,
//         public success: boolean
//     ) { }
// }

class ApiResponse {
    statusCode: number;
    data: any;
    message: string;
    success: boolean

    constructor(statusCode: number, data: any, message: string) {
        this.statusCode = statusCode;
        this.data = data;
        this.message = message;
        this.success = statusCode < 400
    }
}

class ApiError extends Error {
    statusCode: number;
    success: boolean
    data: any
    error: any[];
    override stack?: string

    constructor(statusCode: number, message: string = "Something went wrong", error: any[] = [], stack = '') {
        super(message)
        this.statusCode = statusCode
        this.data = null
        this.error = error
        this.message = message
        this.success = false

        if (stack) {
            this.stack = stack
        } else {
            Error.captureStackTrace(this, this.constructor)
        }
    }
}



export { ApiResponse, ApiError }