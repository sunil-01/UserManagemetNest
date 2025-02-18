import { 
    Controller, Get, Put, Body, Param, UseGuards, Render, Post, 
    Delete, BadRequestException 
  } from '@nestjs/common';
  import { AdminService } from './admin.service';
  import { RolesGuard } from './roles.guard';
  import { Roles } from './roles.decorator';
  import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
  import { AppLogger } from '../common//filters/logger.service';
  
  // Swagger Model for User Registration
  class RegisterUserDto {
    name: string;
    email: string;
    role: string;
  }
  
  // Swagger Model for User Update
  class UpdateUserDto {
    name?: string;
    email?: string;
    role?: string;
    isVerified?: boolean;
  }
  
  // Swagger Model for User ID
  class UserIdDto {
    id: string;
  }
  
  @ApiTags('Admin') // Groups endpoints under "Admin"
  @ApiBearerAuth()  // Adds authentication support in Swagger UI
  @Controller('admin')
  @UseGuards(RolesGuard)
  export class AdminController {
    constructor(
      private readonly adminService: AdminService,
      private readonly logger: AppLogger // ✅ Injecting Winston Logger
    ) {}
  
    @Get()
    @Roles('admin')
    @Render('allusers')
    @ApiOperation({ summary: 'Get all users (Admin Only)' })
    @ApiResponse({ status: 200, description: 'Returns a list of all users' })
    async getAllUsers() {
      this.logger.log('Fetching all users - Admin Access');
      const users = await this.adminService.getAllUsers();
      return { users };
    }
  
    @Post()
    @Roles('admin')
    @ApiOperation({ summary: 'Register a new user (Admin Only)' })
    @ApiResponse({ status: 201, description: 'User successfully registered' })
    @ApiResponse({ status: 400, description: 'Bad Request - Invalid Role' })
    @ApiBody({ 
        schema: {
            example: {
                name: "John Doe",
                email: "john.doe@example.com",
                role: "admin"
            }
        }
    }) 
    async registerUser(@Body() registerUserDto: RegisterUserDto) {
      this.logger.log(`Admin creating new user: ${registerUserDto.email}`);
      
      const user = await this.adminService.register(
          registerUserDto.name, 
          registerUserDto.email, 
          registerUserDto.role
      );
  
      this.logger.log(`User registered successfully: ${registerUserDto.email}`);
      return { message: 'Registration successful! Please verify your email.', user };
    }
  
    @Put('/updateuser')
    @Roles('admin')
    @ApiOperation({ summary: 'Update user details (Admin Only)' })
    @ApiResponse({ status: 200, description: 'User updated successfully' })
    @ApiResponse({ status: 400, description: 'Invalid update request' })
    @ApiBody({ 
        schema: {
            example: {
                id: "123", // Dummy User ID
                name: "Jane Doe",
                email: "jane.doe@example.com",
                role: "Moderator",
                isVerified: true
            }
        }
    }) 
    async updateUser(
        @Body() updateData: UpdateUserDto,
        @Body() userid: UserIdDto
    ) {
      this.logger.log(`Admin updating user ID: ${userid.id}`);
  
      const updatedUser = await this.adminService.updateUser(userid.id, updateData);
      
      this.logger.log(`User updated successfully: ID ${userid.id}`);
      return updatedUser;
    }
  
    @Delete('delete-user')
    @Roles('admin')
    @ApiOperation({ summary: 'Delete a user (Admin Only)' })
    @ApiResponse({ status: 200, description: 'User deleted successfully' })
    @ApiResponse({ status: 400, description: 'Invalid User ID' })
    @ApiBody({
      schema: {
        example: {
          id: "12345"
        }
      },
      description: "Provide the User ID to delete",
      required: true
    })
    async deleteUser(@Body() userIdDto: UserIdDto) {
      try {
        if (!userIdDto.id) {
          this.logger.warn('Delete request received without a user ID');
          throw new BadRequestException('User ID is required');
        }
  
        this.logger.log(`Delete request received for user ID: ${userIdDto.id}`);
        await this.adminService.delete(userIdDto.id);
        this.logger.log(`User deleted successfully: ID ${userIdDto.id}`);
  
        return { message: 'User Deleted Successfully' };
      } 
      catch (error) {
        this.logger.error(`Error deleting user ID ${userIdDto.id}: ${error.message}`);
        throw new BadRequestException(error.message || 'Failed to delete user');
      }
    }
  }
  