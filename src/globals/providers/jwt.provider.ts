import jwt, { Jwt, SignOptions } from 'jsonwebtoken';

interface JwtPayload {
  _id: string;
  email: string;
  name: string;
}

class JwtProvider {
  public async generateJWT(payload: JwtPayload) {
    return jwt.sign(payload, process.env.JWT_SECRET!, {
      expiresIn: process.env.JWT_EXPIRES as SignOptions['expiresIn']
    });
  }

  public verifyJWT(token: string) {
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET!);
      return payload;
    } catch (error) {
      console.log('error', error);
    }
  }
}

export const jwtProvider = new JwtProvider();
