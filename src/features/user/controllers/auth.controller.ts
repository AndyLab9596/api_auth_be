import { Request, Response } from 'express';
import { authService } from '../services/auth.service';
import HTTP_STATUS from '~/globals/constants/http.constant';

class AuthController {
  public async signUp(req: Request, res: Response) {
    const data = await authService.signUp(req.body);
    return res.json({
      message: 'Sign up successfully',
      data
    });
  }

  public async signIn(req: Request, res: Response) {
    const data = await authService.signIn(req.body);
    return res.json({
      message: 'Sign in successfully',
      data
    });
  }

  public async protected(req: Request, res: Response) {
    return res.status(HTTP_STATUS.OK).json({
      message: 'This is a protected route',
      data: req.currentUser
    });
  }

  public async getCurrentUser(req: Request, res: Response) {}

  public async logout(req: Request, res: Response) {}
}

export const authController: AuthController = new AuthController();
