import { Injectable, BadRequestException, NotFoundException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from 'src/DataBase/prisma.service';
import { randomBytes } from 'crypto';
import * as nodemailer from 'nodemailer';
import { DateTime } from 'luxon';
import * as dotenv from 'dotenv';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppLogger } from '../common/filters/logger.service'
dotenv.config(); // Load environment variables

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private logger: AppLogger,
  ) {}

  /**
   * User Registration with Email Verification
   */
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'Registration successful' })
  @ApiResponse({ status: 400, description: 'Email already registered' })
  async register(name: string, email: string, password: string, role: string) {
    this.logger.log(`Attempting to register user: ${email}`);

    const existingUser = await this.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      this.logger.warn(`Registration failed - Email already registered: ${email}`);
      throw new BadRequestException('Email already registered');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = randomBytes(32).toString('hex');

    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role,
        verificationToken,
        isVerified: false,
      },
    });

    this.logger.log(`User registered successfully: ${email}`);
    await this.sendVerificationEmail(user.email, verificationToken);
    return { message: 'Registration successful! Please verify your email.' };
  }

  /**
   * Email Verification
   */
  @ApiOperation({ summary: 'Verify user email' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired verification token' })
  async verifyEmail(token: string) {
    this.logger.log(`Verifying email with token: ${token}`);

    const user = await this.prisma.user.findFirst({ where: { verificationToken: token } });
    if (!user) {
      this.logger.warn(`Email verification failed - Invalid token: ${token}`);
      throw new BadRequestException('Invalid or expired verification token.');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true, verificationToken: null },
    });

    this.logger.log(`Email verified successfully: ${user.email}`);
    return { redirect: '/login' };
  }

  /**
   * Request Password Reset
   */
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({ status: 200, description: 'Password reset link sent' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async forgotPassword(email: string) {
    this.logger.log(`Processing forgot password request for: ${email}`);

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      this.logger.warn(`Forgot password request failed - User not found: ${email}`);
      throw new NotFoundException('User not found.');
    }

    const resetToken = randomBytes(32).toString('hex');
    const resetTokenExpiry = DateTime.now().plus({ hours: 1 }).toJSDate();

    await this.prisma.user.update({ where: { id: user.id }, data: { resetPasswordToken: resetToken, resetTokenExpiry } });
    await this.sendResetPasswordEmail(user.email, resetToken);

    this.logger.log(`Password reset link sent to: ${email}`);
    return { message: 'Password reset link sent to your email.' };
  }

  /**
   * Reset Password
   */
  @ApiOperation({ summary: 'Reset user password' })
  @ApiResponse({ status: 200, description: 'Password reset successful' })
  @ApiResponse({ status: 400, description: 'Invalid or expired reset token' })
  async resetPassword(token: string, newPassword: string) {
    this.logger.log(`Attempting password reset with token: ${token}`);

    const user = await this.prisma.user.findFirst({
      where: { resetPasswordToken: token, resetTokenExpiry: { gt: new Date() } },
    });

    if (!user) {
      this.logger.warn(`Password reset failed - Invalid token: ${token}`);
      throw new BadRequestException('Invalid or expired reset token.');
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.prisma.user.update({ where: { id: user.id }, data: { password: hashedPassword, resetPasswordToken: null, resetTokenExpiry: null } });

    this.logger.log(`Password reset successfully: ${user.email}`);
    return { message: 'Password reset successfully! You can now log in.' };
  }

  /**
   * Send Email Verification Link
   */
  private async sendVerificationEmail(email: string, token: string) {
    const verificationUrl = `${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`;
    await this.sendEmail(email, 'Verify Your Email', `Click here to verify your email: ${verificationUrl}`);
  }

  /**
   * Send Reset Password Link
   */
  private async sendResetPasswordEmail(email: string, token: string) {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await this.sendEmail(email, 'Reset Your Password', `Click here to reset your password: ${resetUrl}`);
  }

  /**
   * Send Email
   */
  private async sendEmail(to: string, subject: string, text: string) {
    try {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER, // Use environment variables
          pass: process.env.EMAIL_PASS,
        },
      });

      await transporter.sendMail({
        from: `"NestJS Auth" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        text,
      });
    } catch (error) {
      console.error('Email Sending Error:', error);
      throw new InternalServerErrorException('Failed to send email. Please try again.');
    }
  }




  /*login api's */

  @ApiOperation({ summary: 'User login' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials or unverified account' })
  async login(email: string, password: string) {
    this.logger.log(`Login attempt for user: ${email}`);

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid email or password');

    if (!(await bcrypt.compare(password, user.password))) {
      this.logger.warn(`Login failed - Incorrect password for: ${email}`);
      throw new UnauthorizedException('Incorrect Password');
    }

    if (!user.isVerified) {
      this.logger.warn(`Login failed - Unverified account: ${email}`);
      throw new UnauthorizedException('Your Account is Not verified');
    }
    
    const tokens = await this.generateTokens(user.id, user.email, user.role);
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    this.logger.log(`User logged in successfully: ${email}`);
    return tokens;
  }

  async verifyUserFromCookies(req: Request) {
    try {
      const accessToken = req.cookies['access_token'];
      if (!accessToken) throw new UnauthorizedException('Access token missing');

      const decoded = this.jwtService.verify(accessToken);
      return decoded; // Returns user payload (userId, email, role)
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired access token');
    }
  }

  async logout(userId: string) {
    this.logger.log(`Logging out user ID: ${userId}`);

    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    this.logger.log(`User logged out successfully: ID ${userId}`);
  }

  @ApiOperation({ summary: 'Refresh authentication token' })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  async refreshToken(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.refreshToken) throw new UnauthorizedException('Access Denied');
    
    const isValid = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!isValid) throw new UnauthorizedException('Invalid refresh token');
    
    const tokens = await this.generateTokens(user.id, user.email, user.role);
    await this.saveRefreshToken(user.id, tokens.refreshToken);
    return tokens;
  }

  private async generateTokens(userId: string, email: string, role: string) {
    const payload = { id: userId, email, role };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: '55m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: '7d',
    });

    return { accessToken, refreshToken,role };
  }

  private async saveRefreshToken(userId: string, refreshToken: string) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);

    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashedToken },
    });
  }
}
