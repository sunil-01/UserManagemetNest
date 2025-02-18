import { Module } from '@nestjs/common';
import { ModeratorService } from './moderator.service';
import { ModeratorController } from './moderator.controller';
import { PrismaModule } from 'src/DataBase/prisma.module';
import { RolesGuard } from '../Admin/roles.guard';  // Ensure role-based access
import { AppLogger } from 'src/common/filters/logger.service';

@Module({
    imports:[PrismaModule],
    controllers: [ModeratorController],
    providers: [ModeratorService,RolesGuard,AppLogger],
})
export class ModeratorModule {}
