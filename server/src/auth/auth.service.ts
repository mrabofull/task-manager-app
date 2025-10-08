import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { UsersService } from 'src/users/users.service';
import { MailService } from './services/mail.service';
import { VerificationCode } from './entities/verification-code.entity';
import { MoreThan, Repository } from 'typeorm';
import { SignupDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { LoginDto } from './dto/login.dto';
import { Response } from 'express';
import { ResendVerificationDto } from './dto/resend-verification.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private mailService: MailService,
    @InjectRepository(VerificationCode)
    private verificationCodeRepository: Repository<VerificationCode>,
    private configService: ConfigService,
  ) {}

  async signup(signupDto: SignupDto) {
    // Check if user exists
    const existingUser = await this.usersService.findByEmail(signupDto.email);
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Hash password
    // const saltRounds = this.configService.get<number>('BCRYPT_SALT_ROUNDS', 10);
    //const passwordHash = await bcrypt.hash(signupDto.password, saltRounds);
    const saltRounds = 10; // Just use a fixed number
    const passwordHash = await bcrypt.hash(signupDto.password, saltRounds);

    // Create user
    const user = await this.usersService.create(signupDto.email, passwordHash);

    // Generate verification code
    const code = this.generateVerificationCode();
    const codeHash = await bcrypt.hash(code, saltRounds);

    // Save verification code
    const verificationCode = this.verificationCodeRepository.create({
      user,
      codeHash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    });
    await this.verificationCodeRepository.save(verificationCode);

    // Send email (mock)
    await this.mailService.sendVerificationEmail(user.email, code);

    return {
      message:
        'User registered successfully. Please check your email for verification code.',
      email: user.email,
    };
  }

  async verifyEmail(verifyDto: VerifyEmailDto, response: Response) {
    const user = await this.usersService.findByEmail(verifyDto.email);
    if (!user) {
      throw new BadRequestException('Invalid email or code');
    }

    if (user.emailVerifiedAt) {
      throw new BadRequestException('Email already verified');
    }

    // Find valid verification code
    const verificationCodes = await this.verificationCodeRepository.find({
      where: {
        user: { id: user.id },
        expiresAt: MoreThan(new Date()),
      },
      order: { createdAt: 'DESC' },
    });

    if (!verificationCodes.length) {
      throw new BadRequestException('No valid verification code found');
    }

    // Check code
    const validCode = verificationCodes.find((vc) =>
      bcrypt.compareSync(verifyDto.code, vc.codeHash),
    );

    if (!validCode) {
      throw new BadRequestException('Invalid verification code');
    }

    // Mark email as verified
    await this.usersService.markEmailAsVerified(user.id);

    // Delete used verification codes
    await this.verificationCodeRepository.delete({ user: { id: user.id } });

    // Generate JWT
    const payload = { sub: user.id, email: user.email };
    const token = this.jwtService.sign(payload);

    // Set HttpOnly cookie
    response.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    return {
      message: 'Email verified successfully. You are now logged in!',
      user: { id: user.id, email: user.email },
    };
  }

  async login(loginDto: LoginDto, response: Response) {
    const user = await this.usersService.findByEmail(loginDto.email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.usersService.unlockIfExpired(user);

    // Check if account is locked
    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
      const minutesLeft = Math.ceil(
        (user.lockoutUntil.getTime() - Date.now()) / 60000,
      );
      throw new UnauthorizedException(
        `Account is locked. Try again in ${minutesLeft} minute(s).`,
      );
    }

    // Check if email is verified
    if (!user.emailVerifiedAt) {
      throw new UnauthorizedException(
        'Please verify your email before logging in',
      );
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      await this.usersService.incrementFailedLoginAttempts(user);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset failed attempts on successful login
    if (user.failedLoginCount > 0) {
      await this.usersService.resetFailedLoginAttempts(user);
    }

    // Generate JWT
    const payload = { sub: user.id, email: user.email };
    const token = this.jwtService.sign(payload);

    // Set HttpOnly cookie
    response.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    return {
      message: 'Login successful',
      user: { id: user.id, email: user.email },
    };
  }

  async logout(response: Response) {
    response.clearCookie('access_token');
    return { message: 'Logged out successfully' };
  }

  private generateVerificationCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  async resendVerificationCode(resendDto: ResendVerificationDto) {
    const user = await this.usersService.findByEmail(resendDto.email);

    if (!user) {
      return {
        message:
          'If an account exists with this email, a new verification code has been sent.',
      };
    }

    if (user.emailVerifiedAt) {
      throw new BadRequestException('Email is already verified');
    }

    await this.verificationCodeRepository.delete({ user: { id: user.id } });

    // Generate new verification code
    const code = this.generateVerificationCode();
    const saltRounds = 10;
    const codeHash = await bcrypt.hash(code, saltRounds);

    // Save new verification code
    const verificationCode = this.verificationCodeRepository.create({
      user,
      codeHash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    });
    await this.verificationCodeRepository.save(verificationCode);

    // Send email
    await this.mailService.sendVerificationEmail(user.email, code);

    return {
      message: 'A new verification code has been sent to your email.',
      email: user.email,
    };
  }
}
