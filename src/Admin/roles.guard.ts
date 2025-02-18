import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';

interface AuthenticatedRequest extends Request {
    user?: any;  // Adjust 'any' based on your user type
}
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRole = this.reflector.get<string>('role', context.getHandler());
    if (!requiredRole) return true; // If no role is required, allow access

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user; 

    if (!user || user.role !== requiredRole) {
      throw new ForbiddenException('Access denied');
    }

    return true; // Allow access
  }
}
