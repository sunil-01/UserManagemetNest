import { 
  Controller, Get, UseGuards, Render, Req 
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ModeratorService } from './moderator.service';
import { RolesGuard } from '../Admin/roles.guard';
import { Roles } from '../Admin/roles.decorator';
import { Request } from 'express';
import { AppLogger } from '../common/filters/logger.service'; // ✅ Winston Logger

interface AuthenticatedRequest extends Request {
  user?: { id: string; email: string; role: string };
}

@ApiTags('Moderator') // Grouping under 'Moderator' category in Swagger
@Controller('moderator')
@UseGuards(RolesGuard)
export class ModeratorController {
  constructor(
      private readonly moderatorService: ModeratorService,
      private readonly logger: AppLogger // ✅ Injecting Winston Logger
  ) {}

  @Get()
  @Roles('moderator')
  @Render('moderator')
  @ApiOperation({ summary: 'Get all users (Moderator Access)' })
  @ApiResponse({ status: 200, description: 'Users retrieved successfully' })
  async getAllUsers(@Req() req: AuthenticatedRequest) {
      this.logger.log('Moderator fetching all users...');

      let user_id = req.user?.id;
      const users = await this.moderatorService.getUser(user_id);

      this.logger.log(`Moderator fetched ${users.length} users.`);
      return { users };
  }
}
