import { BadRequestException } from '~/globals/cores/error.core';
import { UserModel } from '../models/user.model';
import bcrypt from 'bcrypt';
import { jwtProvider } from '~/globals/providers/jwt.provider';

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
    const JwtPayload = {
      _id: createdUser._id.toString(),
      name: createdUser.name,
      email: createdUser.email
    };

    const accessToken = await jwtProvider.generateJWT(JwtPayload);

    return {
      accessToken,
      user: JwtPayload
    };
  }

  public async signIn(requestBody: any) {
    const { email, password } = requestBody;
    const userByEmail = await UserModel.findOne({ email });
    if (!userByEmail) {
      throw new BadRequestException('Invalid credential');
    }

    const isMatch = bcrypt.compare(password, userByEmail.password);
    if (!isMatch) {
      throw new BadRequestException('Invalid credential');
    }

    const JwtPayload = {
      _id: userByEmail._id.toString(),
      name: userByEmail.name,
      email: userByEmail.email
    };

    const accessToken = await jwtProvider.generateJWT(JwtPayload);
    return {
      accessToken,
      user: JwtPayload
    };
  }
}

export const authService: AuthService = new AuthService();
