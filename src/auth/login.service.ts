// import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
// import * as bcrypt from 'bcryptjs';
// import { PrismaService } from 'src/DataBase/prisma.service';
// import { JwtService } from '@nestjs/jwt';
// import { ConfigService } from '@nestjs/config';

// @Injectable()
// export class AuthService {
//   constructor(
//     private prisma: PrismaService,
//     private jwtService: JwtService,
//     private configService: ConfigService,
//   ) {}

//   async login(email: string, password: string) {
//     const user = await this.prisma.user.findUnique({ where: { email } });
//     if (!user || !(await bcrypt.compare(password, user.password))) {
//       throw new UnauthorizedException('Invalid credentials');
//     }

//     const tokens = await this.generateTokens(user.id, user.email, user.role);
//     await this.saveRefreshToken(user.id, tokens.refreshToken);

//     return tokens;
//   }

//   async logout(userId: string) {
//     await this.prisma.user.update({
//       where: { id: userId },
//       data: { refreshToken: null },
//     });
//   }

//   async refreshToken(userId: string, refreshToken: string) {
//     const user = await this.prisma.user.findUnique({ where: { id: userId } });
//     if (!user || !user.refreshToken) throw new UnauthorizedException('Access Denied');

//     const isValid = await bcrypt.compare(refreshToken, user.refreshToken);
//     if (!isValid) throw new UnauthorizedException('Invalid refresh token');

//     const tokens = await this.generateTokens(user.id, user.email, user.role);
//     await this.saveRefreshToken(user.id, tokens.refreshToken);

//     return tokens;
//   }

//   private async generateTokens(userId: string, email: string, role: string) {
//     const payload = { sub: userId, email, role };

//     const accessToken = this.jwtService.sign(payload, {
//       secret: this.configService.get<string>('JWT_SECRET'),
//       expiresIn: '15m',
//     });

//     const refreshToken = this.jwtService.sign(payload, {
//       secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
//       expiresIn: '7d',
//     });

//     return { accessToken, refreshToken };
//   }

//   private async saveRefreshToken(userId: string, refreshToken: string) {
//     const hashedToken = await bcrypt.hash(refreshToken, 10);

//     await this.prisma.user.update({
//       where: { id: userId },
//       data: { refreshToken: hashedToken },
//     });
//   }
// }
