# Authentication-node-package
API Reference
User Model
User Schema
username (String, required, unique): The username of the user.
email (String, required, unique): The email address of the user.
password (String, required): The hashed password of the user.
roles (Array of Strings, default: ['user']): The roles assigned to the user.
Functions
hashPassword(password: string): Promise<string>
Hashes the provided password using bcrypt.
Returns the hashed password.
comparePasswords(password: string, hashedPassword: string): Promise<boolean>
Compares the provided password with the hashed password.
Returns true if the passwords match, false otherwise.
generateToken(user: object): string
Generates a JWT token for the given user object.
Returns the generated token.
authenticateToken(req: express.Request, res: express.Response, next: express.NextFunction): void
Middleware function to authenticate incoming requests using JWT.
Calls next() if the token is valid and adds the user object to req.user.
Sends a 403 Forbidden response if the token is invalid.
