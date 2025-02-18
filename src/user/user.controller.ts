import { 
  Controller, Get, Put, Body, UseGuards, Render, Req 
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { UserService } from './user.service';
import { RolesGuard } from '../Admin/roles.guard';
import { Roles } from '../Admin/roles.decorator';
import { Request } from 'express';
import { AppLogger } from '../common/filters/logger.service'; // ✅ Winston Logger

interface AuthenticatedRequest extends Request {
  user?: { id: string; email: string; role: string };
}

class UpdateUserDto {
  name?: string;
  email?: string;
  role?: string;
  isVerified?: boolean;
}

class UserIdDto {
  id: string;
}

@ApiTags('User') // Grouping under 'User' category in Swagger
@Controller('user')
@UseGuards(RolesGuard)
export class UserController {
  constructor(
      private readonly userService: UserService,
      private readonly logger: AppLogger // ✅ Injecting Winston Logger
  ) {}

  @Get()
  @Roles('user')
  @Render('user')
  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({ status: 200, description: 'Users retrieved successfully' })
  async getAllUsers(@Req() req: AuthenticatedRequest) {
      this.logger.log('Fetching all users...');
      
      let user_id = req.user?.id;
      const users = await this.userService.getUser(user_id);

      this.logger.log(`Fetched ${users.length} users.`);
      return { users };
  }

  @Put('/updateuser')
  @Roles('user')
  @ApiOperation({ summary: 'Update user details' })
  @ApiResponse({ status: 200, description: 'User updated successfully' })
  @ApiBody({ 
      schema: {
          example: {
              id: "123",  // Dummy User ID
              name: "Jane Doe",
              email: "janedoe@example.com",
              role: "admin",
              isVerified: true
          }
      }
  }) 
  async updateUser(
      @Body() updateData: UpdateUserDto,
      @Body() userid: UserIdDto
  ) {
      this.logger.log(`Attempting to update user ID: ${userid.id}`);

      const updatedUser = await this.userService.updateUser(userid.id, updateData);

      this.logger.log(`User updated successfully: ID ${userid.id}`);
      return updatedUser;
  }
}
