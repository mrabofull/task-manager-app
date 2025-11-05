import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { UsersService } from 'src/users/users.service';
import { MailService } from './services/mail.service';
import { VerificationCode } from './entities/verification-code.entity';
import { IsNull, MoreThan, Repository } from 'typeorm';
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

    const normalizedEmail = this.normalizeEmail(signupDto.email);

    // Check if user exists
    const existingUser = await this.usersService.findByEmail(normalizedEmail);
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
      normalizedEmail,
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

    // const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    // console.log('Local display:', expiresAt);
    // console.log('As UTC ISO:', expiresAt.toISOString());

    await this.verificationCodeRepository.save(verificationCode);

    // Send email
    await this.mailService.sendVerificationEmail(normalizedEmail, code);

    return {
      message:
        'Account created successfully. Please check your email for verification code.',
      email: normalizedEmail,
      expiresAt: verificationCode.expiresAt,
    };
  }

  async verifyEmail(
    verifyDto: VerifyEmailDto,
    request: Request,
    response: Response,
  ) {
    const clientIp = this.getClientIp(request);
    const ipAllowed = await this.checkIpAllowlist(clientIp);

    if (!ipAllowed) {
      throw new ForbiddenException(
        'Verifying is restricted from your location.',
      );
    }

    const normalizedEmail = this.normalizeEmail(verifyDto.email);

    const user = await this.usersService.findByEmail(normalizedEmail);
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
      normalizedEmail,
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
        email: normalizedEmail,
        name: user.name,
      },
    };
  }

  async login(loginDto: LoginDto, request: Request, response: Response) {
    const normalizedEmail = this.normalizeEmail(loginDto.email);
    const clientIp = this.getClientIp(request);

    // Check IP allowlist
    const ipAllowed = await this.checkIpAllowlist(clientIp);

    if (!ipAllowed) {
      throw new ForbiddenException('Login is restricted from your location.');
    }

    await this.checkLockout(normalizedEmail, clientIp);

    const user = await this.usersService.findByEmail(normalizedEmail);

    if (
      !user ||
      !(await bcrypt.compare(loginDto.password, user.passwordHash))
    ) {
      await this.recordFailedLogin(normalizedEmail, clientIp, !!user);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset attempts on successful password verification
    await this.resetLoginAttempts(normalizedEmail);

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
    await this.mailService.sendVerificationEmail(normalizedEmail, code);

    return {
      message: 'Please check your email for verification code.',
      email: normalizedEmail,
      expiresAt: verificationCode.expiresAt,
    };
  }

  async refresh(request: Request, response: Response) {
    const clientIp = this.getClientIp(request);
    const ipAllowed = await this.checkIpAllowlist(clientIp);

    if (!ipAllowed) {
      throw new ForbiddenException(
        'Using the application is restricted from your location.',
      );
    }

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

  async resendVerificationCode(
    resendDto: ResendVerificationDto,
    request: Request,
  ) {
    const clientIp = this.getClientIp(request);
    const ipAllowed = await this.checkIpAllowlist(clientIp);

    if (!ipAllowed) {
      throw new ForbiddenException(
        'Registration is restricted from your location.',
      );
    }

    const normalizedEmail = this.normalizeEmail(resendDto.email);
    const user = await this.usersService.findByEmail(normalizedEmail);

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
    await this.mailService.sendVerificationEmail(normalizedEmail, code);

    return {
      email: normalizedEmail,
      expiresAt: verificationCode.expiresAt,
      message: 'A new verification code has been sent to your email.',
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

  // private getClientIp(request: Request): string {
  //   return (
  //     request.ip ||
  //     request.connection?.remoteAddress ||
  //     request.headers['x-forwarded-for']?.toString().split(',')[0] ||
  //     ''
  //   );
  // }

  private getClientIp(request: Request): string {
    // Check forwarded headers (when behind proxy/load balancer)
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      return forwarded.toString().split(',')[0].trim();
    }

    const realIp = request.headers['x-real-ip'];
    if (realIp) {
      return realIp.toString();
    }

    const ip = request.ip || request.connection?.remoteAddress || '::1';
    return ip === '::1' ? '127.0.0.1' : ip;
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

  private async checkLockout(email: string, ipAddress: string): Promise<void> {
    const normalizedEmail = this.normalizeEmail(email);

    // Check email lockout
    const emailAttempt = await this.loginAttemptRepository.findOne({
      where: { email: normalizedEmail },
      order: { updatedAt: 'DESC' },
    });

    if (emailAttempt) {
      // Check if currently locked
      if (
        emailAttempt.lockoutUntil &&
        new Date(emailAttempt.lockoutUntil) > new Date()
      ) {
        const minutesLeft = Math.ceil(
          (new Date(emailAttempt.lockoutUntil).getTime() - Date.now()) / 60000,
        );
        throw new UnauthorizedException(
          `Account locked. Try again in ${minutesLeft} minute(s).`,
        );
      }

      // If lockout expired, reset counter
      if (
        emailAttempt.lockoutUntil &&
        new Date(emailAttempt.lockoutUntil) <= new Date()
      ) {
        emailAttempt.attemptCount = 0;
        emailAttempt.lockoutUntil = null;
        emailAttempt.lastAttemptAt = new Date();
        await this.loginAttemptRepository.save(emailAttempt);
      }

      // Reset if last attempt was over 2 hours ago
      if (emailAttempt.lastAttemptAt) {
        const hoursSinceLastAttempt =
          (Date.now() - new Date(emailAttempt.lastAttemptAt).getTime()) /
          (1000 * 60 * 60);

        if (hoursSinceLastAttempt > 2) {
          emailAttempt.attemptCount = 0;
          emailAttempt.lockoutUntil = null;
          await this.loginAttemptRepository.save(emailAttempt);
        }
      }
    }

    // Check IP lockout
    const ipAttempt = await this.loginAttemptRepository.findOne({
      where: {
        ipAddress,
        email: IsNull(),
      },
      order: { updatedAt: 'DESC' },
    });

    if (ipAttempt) {
      // Check if currently locked
      if (
        ipAttempt.lockoutUntil &&
        new Date(ipAttempt.lockoutUntil) > new Date()
      ) {
        const minutesLeft = Math.ceil(
          (new Date(ipAttempt.lockoutUntil).getTime() - Date.now()) / 60000,
        );
        throw new UnauthorizedException(
          `Too many attempts from this location. Try again in ${minutesLeft} minute(s).`,
        );
      }

      // If lockout expired, reset counter
      if (
        ipAttempt.lockoutUntil &&
        new Date(ipAttempt.lockoutUntil) <= new Date()
      ) {
        ipAttempt.attemptCount = 0;
        ipAttempt.lockoutUntil = null;

        await this.loginAttemptRepository.save(ipAttempt);
      }

      // Reset IP counter after 1 hour of no attempts
      if (ipAttempt.lastAttemptAt) {
        const hoursSinceLastAttempt =
          (Date.now() - new Date(ipAttempt.lastAttemptAt).getTime()) /
          (1000 * 60 * 60);

        if (hoursSinceLastAttempt > 1) {
          ipAttempt.attemptCount = 0;
          ipAttempt.lockoutUntil = null;
          await this.loginAttemptRepository.save(ipAttempt);
        }
      }
    }
  }

  private async recordFailedLogin(
    email: string,
    ipAddress: string,
    userExists: boolean,
  ): Promise<void> {
    const normalizedEmail = this.normalizeEmail(email);

    // Only track existing users for email-based lockout
    if (userExists) {
      let emailAttempt = await this.loginAttemptRepository.findOne({
        where: { email: normalizedEmail },
      });

      if (!emailAttempt) {
        emailAttempt = this.loginAttemptRepository.create({
          email: normalizedEmail,
          ipAddress, // Store which IP attempted this email
          attemptCount: 0,
        });
      }

      // Update IP address to track where attempt came from
      emailAttempt.ipAddress = ipAddress;
      emailAttempt.attemptCount++;
      emailAttempt.lastAttemptAt = new Date();

      // Lock after 3 attempts for 2 minutes
      if (emailAttempt.attemptCount === 3) {
        emailAttempt.lockoutUntil = new Date(Date.now() + 2 * 60 * 1000);
      }

      await this.loginAttemptRepository.save(emailAttempt);
    }

    // Track IP attempts separately (for all attempts, even non-existent users)
    let ipAttempt = await this.loginAttemptRepository.findOne({
      where: {
        ipAddress,
        email: IsNull(),
      },
    });

    if (!ipAttempt) {
      ipAttempt = this.loginAttemptRepository.create({
        ipAddress,
        attemptCount: 0,
        // email is explicitly null for IP-only records
      });
    }

    ipAttempt.attemptCount++;
    ipAttempt.lastAttemptAt = new Date();

    // Lock IP after 10 attempts for 15 minutes
    if (ipAttempt.attemptCount === 10) {
      ipAttempt.lockoutUntil = new Date(Date.now() + 15 * 60 * 1000);
    }

    await this.loginAttemptRepository.save(ipAttempt);
  }

  private async resetLoginAttempts(email: string): Promise<void> {
    const normalizedEmail = this.normalizeEmail(email);
    await this.loginAttemptRepository.delete({ email: normalizedEmail });
  }

  private normalizeEmail(email: string): string {
    return email.toLowerCase().trim();
  }

  async getIpAllowlist() {
    const allowlist = await this.ipAllowlistRepository.find({
      order: { createdAt: 'DESC' },
    });
    return allowlist;
  }

  async addIpToAllowlist(ip: string, label?: string) {
    // Validate IP format
    const ipRegex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipRegex.test(ip)) {
      throw new BadRequestException('Invalid IP address format');
    }

    // Check if already exists
    const existing = await this.ipAllowlistRepository.findOne({
      where: { ip },
    });

    if (existing) {
      throw new ConflictException('IP address already in allowlist');
    }

    const entry = this.ipAllowlistRepository.create({
      ip,
      label: label || `Added ${new Date().toLocaleDateString()}`,
      isActive: true,
    });

    return this.ipAllowlistRepository.save(entry);
  }

  async removeIpFromAllowlist(id: string) {
    const entry = await this.ipAllowlistRepository.findOne({
      where: { id },
    });

    if (!entry) {
      throw new NotFoundException('IP entry not found');
    }

    await this.ipAllowlistRepository.delete(id);
    return { message: 'IP removed successfully' };
  }
}
