import { NextFunction, Request, Response } from 'express';
import { jwtProvider } from '../providers/jwt.provider';
import { BadRequestException, UnAuthorizedException } from '../cores/error.core';
import { JwtPayload } from 'jsonwebtoken';

class AuthMiddleware {
  public async verifyUser(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!req.headers.authorization || !token) {
      throw new UnAuthorizedException('You are not logged in');
    }

    const decoded = jwtProvider.verifyJWT(token);
    if (!decoded) {
      throw new UnAuthorizedException('You are not logged in');
    }
    req.currentUser = {
      _id: (decoded as JwtPayload)._id,
      name: (decoded as JwtPayload).name,
      email: (decoded as JwtPayload).email,
      role: ''
    };
    next();
  }
}

export const authMiddleware: AuthMiddleware = new AuthMiddleware();
