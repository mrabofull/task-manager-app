import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
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
import { Response, Request } from 'express';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { IpAllowlist } from './entities/ip-allowlist.entity';
import { SessionService } from './services/session.service';
import { LoginAttempt } from './entities/login-attempt.entity';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private mailService: MailService,
    @InjectRepository(VerificationCode)
    private verificationCodeRepository: Repository<VerificationCode>,
    @InjectRepository(IpAllowlist)
    private ipAllowlistRepository: Repository<IpAllowlist>,
    private sessionService: SessionService,
    private configService: ConfigService,
    @InjectRepository(LoginAttempt)
    private loginAttemptRepository: Repository<LoginAttempt>,
  ) {}

  async signup(signupDto: SignupDto, request: Request) {
    const clientIp = this.getClientIp(request);
    const ipAllowed = await this.checkIpAllowlist(clientIp);

    if (!ipAllowed) {
      throw new ForbiddenException(
        'Registration is restricted from your location.',
      );
    }

    // Check if user exists
    const existingUser = await this.usersService.findByEmail(signupDto.email);
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Hash password
    // const saltRounds = this.configService.get<number>('BCRYPT_SALT_ROUNDS', 10);
    //const passwordHash = await bcrypt.hash(signupDto.password, saltRounds);
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(signupDto.password, saltRounds);

    // Create user
    const user = await this.usersService.create(
      signupDto.email,
      signupDto.name,
      passwordHash,
    );

    // Generate verification code
    const code = this.generateVerificationCode();
    const codeHash = await bcrypt.hash(code, saltRounds);

    // Save verification code
    const verificationCode = this.verificationCodeRepository.create({
      user,
      codeHash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    });

    // To del
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    console.log('Local display:', expiresAt);
    console.log('As UTC ISO:', expiresAt.toISOString());
    //

    await this.verificationCodeRepository.save(verificationCode);

    // Send email
    await this.mailService.sendVerificationEmail(user.email, code);

    return {
      message:
        'Account created successfully. Please check your email for verification code.',
      email: user.email,
      expiresAt: verificationCode.expiresAt,
    };
  }

  async verifyEmail(
    verifyDto: VerifyEmailDto,
    request: Request,
    response: Response,
  ) {
    const user = await this.usersService.findByEmail(verifyDto.email);
    if (!user) {
      throw new BadRequestException('Invalid email or code');
    }

    const latestCode = await this.verificationCodeRepository.findOne({
      where: {
        user: { id: user.id },
        expiresAt: MoreThan(new Date()),
      },
      order: { createdAt: 'DESC' },
    });

    if (!latestCode) {
      throw new BadRequestException('Verification code expired');
    }

    if (!bcrypt.compareSync(verifyDto.code, latestCode.codeHash)) {
      throw new BadRequestException('Invalid verification code');
    }

    // Update emailVerifiedAt only if not already verified
    if (!user.emailVerifiedAt) {
      await this.usersService.markEmailAsVerified(user.id);
    }

    const { accessToken, refreshToken } = await this.generateTokens(
      user.id,
      user.email,
      user.name,
    );

    // Create session with device info
    const userAgent = this.getUserAgent(request);
    const ipAddress = this.getClientIp(request);
    await this.sessionService.createSession(
      user,
      refreshToken,
      userAgent,
      ipAddress,
    );

    // Set cookies
    this.setTokenCookies(response, accessToken, refreshToken);

    return {
      message: 'Successfully logged in',
      user: {
        email: user.email,
        name: user.name,
      },
    };
  }

  async login(loginDto: LoginDto, request: Request, response: Response) {
    const clientIp = this.getClientIp(request);

    // Check hybrid lockout (IP + account)
    const isLocked = await this.checkHybridLockout(loginDto.email, clientIp);
    if (isLocked.locked) {
      throw new UnauthorizedException(isLocked.message);
    }

    // Check IP allowlist
    const ipAllowed = await this.checkIpAllowlist(clientIp);

    if (!ipAllowed) {
      throw new ForbiddenException('Login is restricted from your location.');
    }

    const user = await this.usersService.findByEmail(loginDto.email);

    if (
      !user ||
      !(await bcrypt.compare(loginDto.password, user.passwordHash))
    ) {
      await this.recordFailedAttempt(loginDto.email, clientIp);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset attempts on successful password verification
    await this.resetLoginAttempts(loginDto.email, clientIp);

    // Generate and send login verification code
    const code = this.generateVerificationCode();
    const codeHash = await bcrypt.hash(code, 10);

    const verificationCode = this.verificationCodeRepository.create({
      user,
      codeHash,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    });
    await this.verificationCodeRepository.save(verificationCode);

    // Send email
    await this.mailService.sendVerificationEmail(user.email, code);

    return {
      message: 'Please check your email for verification code.',
      email: user.email,
      expiresAt: verificationCode.expiresAt,
    };
  }

  async refresh(request: Request, response: Response) {
    const refreshToken = request.cookies['refresh_token'];

    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }

    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      // Find session
      const session =
        await this.sessionService.findByRefreshToken(refreshToken);
      if (!session) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Update last used
      await this.sessionService.updateLastUsed(session.id);

      // new access token
      const accessToken = this.jwtService.sign({
        sub: session.user.id,
        email: session.user.email,
        name: session.user.name,
      });

      // Update access token cookie
      response.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15m
      });

      return { message: 'Token refreshed' };
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(request: Request, response: Response) {
    const refreshToken = request.cookies['refresh_token'];

    // Delete session if exists
    if (refreshToken) {
      await this.sessionService.deleteSession(refreshToken);
    }

    response.clearCookie('access_token');
    response.clearCookie('refresh_token');

    return { message: 'Logged out successfully' };
  }

  private generateVerificationCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  async resendVerificationCode(resendDto: ResendVerificationDto) {
    const user = await this.usersService.findByEmail(resendDto.email);

    if (!user) {
      return {
        message: 'A new verification code has been sent to your email.',
      };
    }

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

  private async generateTokens(userId: string, email: string, name: string) {
    const payload = { sub: userId, email, name };

    const accessToken = this.jwtService.sign(payload);

    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRATION,
    });

    return { accessToken, refreshToken };
  }

  private setTokenCookies(
    response: Response,
    accessToken: string,
    refreshToken: string,
  ) {
    response.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15m
    });

    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7d
    });
  }

  private getClientIp(request: Request): string {
    return (
      request.ip ||
      request.connection?.remoteAddress ||
      request.headers['x-forwarded-for']?.toString().split(',')[0] ||
      ''
    );
  }

  private getUserAgent(request: Request): string {
    return request.headers['user-agent'] || '';
  }

  private async checkIpAllowlist(ip: string): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') {
      return true;
    }

    const allowedIp = await this.ipAllowlistRepository.findOne({
      where: { ip, isActive: true },
    });

    return !!allowedIp;
  }

  // Hybrid lockout strategy
  private async checkHybridLockout(
    email: string,
    ipAddress: string,
  ): Promise<{ locked: boolean; message?: string }> {
    // Check both email and IP lockouts
    const [emailAttempt, ipAttempt] = await Promise.all([
      this.loginAttemptRepository.findOne({
        where: { email },
        order: { createdAt: 'DESC' },
      }),
      this.loginAttemptRepository.findOne({
        where: { ipAddress },
        order: { createdAt: 'DESC' },
      }),
    ]);

    const now = new Date();

    // Check email lockout
    if (emailAttempt?.lockoutUntil && emailAttempt.lockoutUntil > now) {
      const minutesLeft = Math.ceil(
        (emailAttempt.lockoutUntil.getTime() - now.getTime()) / 60000,
      );
      return {
        locked: true,
        message: `Account locked due to multiple failed attempts. Try again in ${minutesLeft} minute(s).`,
      };
    }

    // Check IP lockout
    if (ipAttempt?.lockoutUntil && ipAttempt.lockoutUntil > now) {
      const minutesLeft = Math.ceil(
        (ipAttempt.lockoutUntil.getTime() - now.getTime()) / 60000,
      );
      return {
        locked: true,
        message: `Too many attempts from this location. Try again in ${minutesLeft} minute(s).`,
      };
    }

    return { locked: false };
  }

  private async recordFailedAttempt(
    email: string,
    ipAddress: string,
  ): Promise<void> {
    // Record for email
    let emailAttempt = await this.loginAttemptRepository.findOne({
      where: { email },
    });

    if (!emailAttempt) {
      emailAttempt = this.loginAttemptRepository.create({
        email,
        ipAddress,
        attemptCount: 0,
      });
    }

    emailAttempt.attemptCount++;

    // Exponential backoff for account
    if (emailAttempt.attemptCount >= 3) {
      const delayMinutes = Math.min(
        Math.pow(2, emailAttempt.attemptCount - 3),
        30,
      );
      emailAttempt.lockoutUntil = new Date(
        Date.now() + delayMinutes * 60 * 1000,
      );
    }

    await this.loginAttemptRepository.save(emailAttempt);

    // Record for IP
    let ipAttempt = await this.loginAttemptRepository.findOne({
      where: { ipAddress },
    });

    if (ipAttempt && ipAttempt.email) {
      ipAttempt = null; // This is an email-specific attempt, not IP-only
    }

    if (!ipAttempt) {
      ipAttempt = this.loginAttemptRepository.create({
        ipAddress,
        attemptCount: 0,
      });
    }

    ipAttempt.attemptCount++;

    // Lock IP after 10 attempts (higher threshold for IP)
    if (ipAttempt.attemptCount >= 10) {
      ipAttempt.lockoutUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    }

    await this.loginAttemptRepository.save(ipAttempt);
  }

  private async resetLoginAttempts(
    email: string,
    ipAddress: string,
  ): Promise<void> {
    await this.loginAttemptRepository.delete({ email });
    // Don't reset IP attempts to track patterns
  }
}
