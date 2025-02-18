import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from './auth.service';

interface AuthenticatedRequest extends Request {
  user?: { id: string; email: string; role: string };  // Adjust 'any' to your user type
}

@Injectable()
export class JwtAuthMiddleware implements NestMiddleware {
  constructor(private authService: AuthService) {}

  async use(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const user = await this.authService.verifyUserFromCookies(req);
      if (!user) {
        throw new UnauthorizedException('Unauthorized access');
      }
      req.user = user;  // Attach the user to the request object
      next(); // Proceed to the next middleware or controller
    } catch (error) {
      next(new UnauthorizedException('Unauthorized access'));
    }
  }
}
