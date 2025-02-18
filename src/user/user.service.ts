import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/DataBase/prisma.service'; // Ensure PrismaService is correctly set up
import { User } from '@prisma/client'; // Import the User type from Prisma
import * as bcrypt from 'bcryptjs';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppLogger } from '../common/filters/logger.service'; // ✅ Winston Logger

@Injectable()
@ApiTags('Users') // Swagger tag for grouping APIs
export class UserService {
  constructor(
    private prisma: PrismaService,
    private readonly logger: AppLogger // ✅ Injecting Winston Logger
  ) {}

  // Fetch user by ID
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiResponse({ status: 200, description: 'User retrieved successfully' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async getUser(userid: string | undefined): Promise<User[]> {
    if (userid !== undefined) {
      this.logger.log(`Fetching user by ID: ${userid}`);

      const user = await this.prisma.user.findUnique({ where: { id: userid } });
      if (!user) {
        this.logger.warn(`User not found: ID ${userid}`);
        throw new NotFoundException('User not found');
      }

      this.logger.log(`User retrieved successfully: ID ${userid}`);
      return [user];
    }

    this.logger.warn('No user_id provided to find the user');
    throw new NotFoundException('No user_id provided to find the user');
  }

  // Register a new user
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'Registration successful' })
  @ApiResponse({ status: 400, description: 'Email already registered' })
  async register(name: string, email: string, role: string) {
    this.logger.log(`Attempting to register user: ${email}`);

    const existingUser = await this.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      this.logger.warn(`Registration failed - Email already registered: ${email}`);
      throw new BadRequestException('Email already registered');
    }

    const hashedPassword = await bcrypt.hash('defaultPassword', 10);

    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        role,
        password: hashedPassword,
        isVerified: true,
      },
    });

    this.logger.log(`User registered successfully: ${email}`);
    return { message: 'Registration successful! Please verify your email.' };
  }

  // Update user details
  @ApiOperation({ summary: 'Update user details' })
  @ApiResponse({ status: 200, description: 'User updated successfully' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async updateUser(
    id: string,
    data: { name?: string; email?: string; role?: string; isVerified?: boolean }
  ) {
    this.logger.log(`Attempting to update user ID: ${id}`);

    const existingUser = await this.prisma.user.findUnique({ where: { id } });

    if (!existingUser) {
      this.logger.warn(`Update failed - User not found: ID ${id}`);
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data,
    });

    this.logger.log(`User updated successfully: ID ${id}`);
    return updatedUser;
  }
}
