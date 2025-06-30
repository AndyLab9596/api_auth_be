import jwt from 'jsonwebtoken';

interface JwtPayload {
  _id: string;
  email: string;
  name: string;
}

class JwtProvider {
  public async generateJWT(payload: JwtPayload) {
    return jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: parseInt(process.env.JWT_EXPIRES!) });
  }
}

export const jwtProvider = new JwtProvider();
