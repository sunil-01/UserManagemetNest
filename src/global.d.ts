import { Request } from 'express';

declare global {
  namespace Express {
    interface Request {
      cookies: {
        [key: string]: string;
      };
    }
  }
}
