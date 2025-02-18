import { Module,MiddlewareConsumer, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './DataBase/prisma.module';
import { AuthModule } from './auth/auth.module';
import { JwtAuthMiddleware } from './auth/jwt-auth.middleware';
import { AuthController } from './auth/auth.controller';
import { RequestMethod } from '@nestjs/common';
import { AdminModule } from './Admin/admin.module';
import { AdminController } from './Admin/admin.controller';
import { UserController } from './user/user.controller';
import { UserModule } from './user/user.module';
import { ModeratorController } from './moderator/moderator.controller';
import { ModeratorModule } from './moderator/moderator.module';
import { AppLogger } from './common//filters/logger.service';

@Module({
  imports: [PrismaModule, AuthModule,AdminModule,UserModule,ModeratorModule],
  controllers: [AppController],
  providers: [AppService,AppLogger],
  exports: [AppLogger]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(JwtAuthMiddleware)
    .exclude(
      { path: 'auth/register', method: RequestMethod.POST },
      { path: 'auth/login', method: RequestMethod.POST },
      { path: 'auth/forgot-password', method: RequestMethod.POST },
      { path: 'auth/reset-password', method: RequestMethod.POST },
      { path: '/reset-password', method: RequestMethod.GET }
    )
    .forRoutes(AuthController,AdminController,UserController,ModeratorController); // Apply middleware to specific routes
  }
}
// pg_ctlcluster 12 main start
// imtg ulgf jcqb oaqv