import { 
  Controller, Post, Body, Query, BadRequestException, UseGuards, Req, Get, Res 
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody, ApiQuery } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Response, Request } from 'express';
import { AppLogger } from '../common/filters/logger.service'

// DTOs for Swagger Documentation
class RegisterUserDto {
  name: string;
  email: string;
  password: string;
}

class LoginDto {
  email: string;
  password: string;
}

class ResetPasswordDto {
  token: string;
  newPassword: string;
}

class RefreshTokenDto {
  userId: string;
  refreshToken: string;
}

interface AuthenticatedRequest extends Request {
  role: string;
  user?: { id: string; email: string; role: string };
}

@ApiTags('Auth') // Groups this controller under "Auth" in Swagger
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly logger: AppLogger
  ) {}

  @ApiOperation({ summary: 'User Registration' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 400, description: 'Email already registered' })
  @ApiBody({
    schema: {
      example: {
        name: "John Doe",
        email: "johndoe@example.com",
        password: "SecurePassword123"
      }
    }
  }) 
  @Post('register')
  async registerUser(@Body() body: RegisterUserDto) {
    this.logger.log(`Registering new user: ${body.email}`);
    
    const user = await this.authService.register(body.name, body.email, body.password, 'User');

    this.logger.log(`User registered successfully: ${body.email}`);
    return { message: 'Registration successful! Please verify your email.', user };
  }

  @ApiOperation({ summary: 'Verify Email using Token' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiResponse({ status: 400, description: 'Verification token is required' })
  @ApiQuery({ 
    name: 'token', 
    required: true, 
    example: 'random-verification-token-123',
    description: 'The verification token sent to the user\'s email' 
  })
  @Get('verify-email')
  async verifyEmail(@Query('token') token: string, @Res() res: Response) {
    if (!token) {
        this.logger.warn('Email verification failed: No token provided');
        throw new BadRequestException('Verification token is required');
    }

    await this.authService.verifyEmail(token);
    this.logger.log('Email verified successfully');
    return res.redirect('/login');
  }

  @ApiOperation({ summary: 'Request Password Reset' })
  @ApiResponse({ status: 200, description: 'Password reset link sent to email' })
  @ApiBody({
    schema: {
      example: {
        email: "johndoe@example.com"
      }
    }
  })
  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
      await this.authService.forgotPassword(email);
      return { message: 'Password reset link sent to your email.' };
  }

  @ApiOperation({ summary: 'Reset Password using Token' })
  @ApiResponse({ status: 200, description: 'Password reset successfully' })
  @ApiBody({ 
    schema: {
      example: {
        token: "random-reset-token-123",
        newPassword: "NewSecurePassword123"
      }
    }
  })
  @Post('reset-password')
  async resetPassword(@Body() body: ResetPasswordDto) {
      await this.authService.resetPassword(body.token, body.newPassword);
      return { message: 'Password reset successfully! You can now log in.' };
  }

  @ApiOperation({ summary: 'User Login' })
  @ApiResponse({ status: 200, description: 'User logged in successfully' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiBody({ 
    schema: {
      example: {
        email: "johndoe@example.com",
        password: "SecurePassword123"
      }
    }
  })
  @Post('login')
  async login(@Body() body: LoginDto, @Res() res: Response) {
    this.logger.log(`Login attempt for user: ${body.email}`);
      try {
          const tokens = await this.authService.login(body.email, body.password);
          
          res.cookie('access_token', tokens.accessToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              sameSite: 'strict',
              maxAge: 55 * 60 * 1000, // 55 minutes
          });

          res.cookie('refresh_token', tokens.refreshToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              sameSite: 'strict',
              maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          });
          this.logger.log(`User logged in successfully: ${body.email}`);
          if (tokens.role === 'admin') return res.redirect('/admin');
          else if (tokens.role === 'user') return res.redirect('/user');
          else if (tokens.role === 'moderator') return res.redirect('/moderator');
          else{
            throw new Error('NO role defined for User')
          }
      } 
      catch (error) {
        this.logger.error(`Login failed for user: ${body.email}`, error.message);
        return res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
      }
  }

  @ApiOperation({ summary: 'User Logout' })
  @ApiResponse({ status: 200, description: 'Logged out successfully' })
  @ApiResponse({ status: 400, description: 'User not found in request' })
  @Get('logout')
  async logout(@Req() req: AuthenticatedRequest, @Res() res: Response) {
      try {
          const userId = req.user?.id;
          if (!userId) {
            this.logger.warn('Logout failed: User not found in request');
            return res.status(400).json({ message: 'User not found in request' });
          }
          await this.authService.logout(userId);
          res.clearCookie('access_token');
          res.clearCookie('refresh_token');

          this.logger.log(`User logged out successfully: ID ${userId}`);
          return res.status(200).json({ message: 'Logged out successfully' });
      } 
      catch (error) {
        this.logger.error('Logout Error', error.message);
        return res.status(500).json({ message: 'Internal server error' });
      }
  }

  @ApiOperation({ summary: 'Refresh Access Token' })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  @ApiBody({ 
    schema: {
      example: {
        userId: "12345",
        refreshToken: "random-refresh-token-678"
      }
    }
  })
  @Post('refresh')
  async refreshToken(@Body() body: RefreshTokenDto) {
      return this.authService.refreshToken(body.userId, body.refreshToken);
  }
}
