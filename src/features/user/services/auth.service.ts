import { BadRequestException } from '~/globals/cores/error.core';
import { UserModel } from '../models/user.model';
import bcrypt from 'bcrypt';

class AuthService {
  public async signUp(requestBody: any) {
    const { email, name, password } = requestBody;

    const userByEmail = await UserModel.findOne({ email });
    if (userByEmail) {
      throw new BadRequestException('User with email is already exists');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await UserModel.create({
      name,
      email,
      password: hashedPassword
    });

    const createdUser = await user.save();
    console.log(createdUser);

    return {
      accessToken: ''
    };
  }

  public async signIn(requestBody: any) {}
}

export const authService: AuthService = new AuthService();
