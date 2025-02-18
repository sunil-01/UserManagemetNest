import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/DataBase/prisma.service'; // Ensure PrismaService is correctly set up
import { User } from '@prisma/client'; // Import the User type from Prisma
import * as bcrypt from 'bcryptjs';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppLogger } from '../common/filters/logger.service'; // ✅ Winston Logger

// Swagger DTO for User Registration
class RegisterUserDto {
    name: string;
    email: string;
    role: string;
}

// Swagger DTO for User Update
class UpdateUserDto {
    name?: string;
    email?: string;
    role?: string;
    isVerified?: boolean;
}

@ApiTags('Admin Service') // Groups this service under "Admin Service" in Swagger
@Injectable()
export class AdminService {
    constructor(
        private prisma: PrismaService,
        private readonly logger: AppLogger 
    ) {}

    @ApiOperation({ summary: 'Fetch all users' })
    @ApiResponse({ status: 200, description: 'Returns all users' })
    async getAllUsers(): Promise<User[]> {
        this.logger.log('Fetching all users...');
        const users = await this.prisma.user.findMany();
        this.logger.log(`Fetched ${users.length} users.`);
        return users;
    }

    @ApiOperation({ summary: 'Register a new user' })
    @ApiResponse({ status: 201, description: 'User registered successfully' })
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
                isVerified: true 
            },
        });

        this.logger.log(`User registered successfully: ${email}`);
        return { message: 'Registration successful! Please verify your email.', user };
    }

    @ApiOperation({ summary: 'Update user details' })
    @ApiResponse({ status: 200, description: 'User updated successfully' })
    @ApiResponse({ status: 404, description: 'User not found' })
    async updateUser(id: string, data: UpdateUserDto) {
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

    @ApiOperation({ summary: 'Delete a user by ID' })
    @ApiResponse({ status: 200, description: 'User deleted successfully' })
    @ApiResponse({ status: 404, description: 'User not found' })
    async delete(id: string): Promise<{ message: string }> {
        this.logger.log(`Attempting to delete user ID: ${id}`);
        
        const existingUser = await this.prisma.user.findUnique({ where: { id: id } });

        if (!existingUser) {
            this.logger.warn(`Delete failed - User not found: ID ${id}`);
            throw new NotFoundException(`User with ID ${id} not found`);
        }

        await this.prisma.user.delete({ where: { id: id } });

        this.logger.log(`User deleted successfully: ID ${id}`);
        return { message: `User with ID ${id} deleted successfully` };
    }
}
