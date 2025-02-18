import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PrismaModule } from 'src/DataBase/prisma.module';
import { JwtAuthMiddleware } from './jwt-auth.middleware';
import { AppLogger } from 'src/common/filters/logger.service';


@Module({
  imports: [
    ConfigModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '55m' },
      }),
    }),
    PrismaModule
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy,JwtAuthMiddleware,AppLogger],
  exports:[AuthService,JwtAuthMiddleware]
})
export class AuthModule {}

