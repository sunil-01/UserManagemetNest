import { Module } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { PrismaModule } from 'src/DataBase/prisma.module';
import { RolesGuard } from './roles.guard';
import { AppLogger } from '../common//filters/logger.service';

@Module({
    imports:[PrismaModule],
    controllers: [AdminController],
    providers: [AdminService,RolesGuard,AppLogger],
})
export class AdminModule {}
