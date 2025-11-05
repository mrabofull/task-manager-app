import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { MailService } from './services/mail.service';
import { SignupDto } from './dto/signup.dto';
import { Throttle } from '@nestjs/throttler';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { LoginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly mailService: MailService,
  ) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async signup(@Body() signupDto: SignupDto, @Req() request: Request) {
    return this.authService.signup(signupDto, request);
  }

  @Post('verify')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async verifyEmail(
    @Body() verifyEmailDto: VerifyEmailDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.verifyEmail(verifyEmailDto, request, response);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async login(
    @Body() loginDto: LoginDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(loginDto, request, response);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.refresh(request, response);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.logout(request, response);
  }

  @Get('dev/mailbox')
  async getMailbox() {
    return {
      message: 'Mock email outbox',
      emails: await this.mailService.getOutbox(),
    };
  }

  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 3, ttl: 300000 } }) // 3 requests per 5 minutes, 6000 = 1m (300000ms)
  async resendVerificationCode(
    @Body() resendDto: ResendVerificationDto,
    @Req() request: Request,
  ) {
    return this.authService.resendVerificationCode(resendDto, request);
  }

  @Get('admin/ip-allowlist')
  @UseGuards(JwtAuthGuard)
  async getIpAllowlist(@Req() request: any) {
    // Simple admin check by email
    if (request.user.email !== process.env.ADMIN_EMAIL) {
      throw new ForbiddenException('Admin access only');
    }
    return this.authService.getIpAllowlist();
  }

  @Post('admin/ip-allowlist')
  @UseGuards(JwtAuthGuard)
  async addIpToAllowlist(
    @Body() dto: { ip: string; label?: string },
    @Req() request: any,
  ) {
    if (request.user.email !== process.env.ADMIN_EMAIL) {
      throw new ForbiddenException('Admin access only');
    }
    return this.authService.addIpToAllowlist(dto.ip, dto.label);
  }

  @Delete('admin/ip-allowlist/:id')
  @UseGuards(JwtAuthGuard)
  async removeIpFromAllowlist(@Param('id') id: string, @Req() request: any) {
    if (request.user.email !== process.env.ADMIN_EMAIL) {
      throw new ForbiddenException('Admin access only');
    }
    return this.authService.removeIpFromAllowlist(id);
  }
}
