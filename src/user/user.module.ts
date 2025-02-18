import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { PrismaModule } from 'src/DataBase/prisma.module';
import { RolesGuard } from '../Admin/roles.guard';  // Ensure role-based access
import { AppLogger } from '../common//filters/logger.service';

@Module({
    imports:[PrismaModule],
    controllers: [UserController],
    providers: [UserService,RolesGuard,AppLogger],
})
export class UserModule {}
