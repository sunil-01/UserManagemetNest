import { Controller, Get, Query, Render } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiQuery } from '@nestjs/swagger';

@ApiTags('Auth Pages') // Group these routes under "Auth Pages" in Swagger
@Controller()
export class AppController {
  getHello(): any {
    throw new Error('Method not implemented.');
  }

  @Get('register')
  @Render('register')
  @ApiOperation({ summary: 'Render the registration page' })
  @ApiQuery({ name: 'error', required: false, description: 'Error message (if any)' })
  showRegisterPage(@Query('error') error: string) {
    return { error };
  }

  @Get('login')
  @Render('login')
  @ApiOperation({ summary: 'Render the login page' })
  @ApiQuery({ name: 'error', required: false, description: 'Error message (if any)' })
  showLoginPage(@Query('error') error: string) {
    return { error };
  }

  @Get('forgot-password')
  @Render('forgot-password')
  @ApiOperation({ summary: 'Render the forgot password page' })
  showForgotPasswordPage() {
    return { error: null, success: null };
  }

  @Get('reset-password')
  @Render('reset-password')
  @ApiOperation({ summary: 'Render the reset password page' })
  @ApiQuery({ 
    name: 'token', 
    required: true, 
    example: 'random-verification-token-123',
    description: 'The verification token sent to the user\'s email' 
})
  async showResetPasswordPage(@Query('token') token: string) {
    if (!token) {
      return { error: 'Token is missing or invalid.' };
    }
    return { error: null, success: null, token };
  }
}
