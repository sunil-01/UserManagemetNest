import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';  // Ensure Express Request is imported
import { AuthService } from './auth.service';


interface AuthenticatedRequest extends Request {
  user?: any;  // Adjust 'any' based on your user type
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>(); // Explicitly cast as Express Request

    try {
      const user = await this.authService.verifyUserFromCookies(request);
      request.user = user;  // Use "any" to avoid strict typing issues
      return true;
    } catch (error) {
      throw new UnauthorizedException('Unauthorized access');
    }
  }
}
