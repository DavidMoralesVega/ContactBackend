import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Req,
  Headers,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
} from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { RawHeaders, GetUser, Auth } from './decorators';
import { RoleProtected } from './decorators/role-protected.decorator';

import { CreateUserDto, LoginUserDto } from './dto';
import { User } from './entities/user.entity';
import { UserRoleGuard } from './guards/user-role.guard';
import { ValidRoles } from './interfaces';
import type { IncomingHttpHeaders } from 'http';

@ApiTags('🔐 Authentication & Authorization')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({
    summary: '👤 Register a new user',
    description:
      'Creates a new user account. The password must contain at least one uppercase letter, one lowercase letter, and one number. Email must be unique.',
  })
  @ApiBody({
    type: CreateUserDto,
    description: 'User registration data',
    examples: {
      example1: {
        summary: 'Valid registration',
        value: {
          email: 'john.doe@example.com',
          password: 'MySecure123',
          fullName: 'John Doe',
        },
      },
    },
  })
  @ApiResponse({
    status: 201,
    description: '✅ User registered successfully',
    schema: {
      example: {
        id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
        email: 'john.doe@example.com',
        fullName: 'John Doe',
        isActive: true,
        roles: ['user'],
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '❌ Bad request - Validation errors or email already exists',
    schema: {
      example: {
        statusCode: 400,
        message: [
          'email must be an email',
          'The password must have a Uppercase, lowercase letter and a number',
        ],
        error: 'Bad Request',
      },
    },
  })
  createUser(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('login')
  @ApiOperation({
    summary: '🔑 User login',
    description:
      'Authenticates a user with email and password. Returns a JWT token for accessing protected endpoints.',
  })
  @ApiBody({
    type: LoginUserDto,
    description: 'User login credentials',
    examples: {
      example1: {
        summary: 'Valid login',
        value: {
          email: 'john.doe@example.com',
          password: 'MySecure123',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: '✅ Login successful',
    schema: {
      example: {
        id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
        email: 'john.doe@example.com',
        fullName: 'John Doe',
        isActive: true,
        roles: ['user'],
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid credentials',
    schema: {
      example: {
        statusCode: 401,
        message: 'Credentials are not valid (email)',
        error: 'Unauthorized',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '❌ Bad request - Validation errors',
    schema: {
      example: {
        statusCode: 400,
        message: [
          'email must be an email',
          'password must be longer than or equal to 6 characters',
        ],
        error: 'Bad Request',
      },
    },
  })
  loginUser(@Body() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  @Get('check-status')
  @ApiBearerAuth()
  @Auth()
  @ApiOperation({
    summary: '🔍 Check authentication status',
    description:
      'Validates the current JWT token and returns updated user information with a fresh token. Use this to check if the user is still authenticated.',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Token is valid, user authenticated',
    schema: {
      example: {
        id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
        email: 'john.doe@example.com',
        fullName: 'John Doe',
        isActive: true,
        roles: ['user'],
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or expired token',
    schema: {
      example: {
        statusCode: 401,
        message: 'Token not valid',
        error: 'Unauthorized',
      },
    },
  })
  checkAuthStatus(@GetUser() user: User) {
    return this.authService.checkAuthStatus(user);
  }

  @Get('private')
  @UseGuards(AuthGuard())
  @ApiBearerAuth()
  @ApiOperation({
    summary: '🧪 Test private route',
    description:
      'Testing endpoint for authenticated users. Returns user information and request headers. Used for development and testing purposes.',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Private route accessed successfully',
    schema: {
      example: {
        ok: true,
        message: 'Hola Mundo Private',
        user: {
          id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
          email: 'john.doe@example.com',
          fullName: 'John Doe',
          isActive: true,
          roles: ['user'],
        },
        userEmail: 'john.doe@example.com',
        rawHeaders: [
          'authorization',
          'Bearer eyJ...',
          'content-type',
          'application/json',
        ],
        headers: {
          authorization: 'Bearer eyJ...',
          'content-type': 'application/json',
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  testingPrivateRoute(
    @Req() request: Express.Request,
    @GetUser() user: User,
    @GetUser('email') userEmail: string,
    @RawHeaders() rawHeaders: string[],
    @Headers() headers: IncomingHttpHeaders,
  ) {
    return {
      ok: true,
      message: 'Hola Mundo Private',
      user,
      userEmail,
      rawHeaders,
      headers,
    };
  }

  @Get('private2')
  @RoleProtected(ValidRoles.superUser, ValidRoles.admin)
  @UseGuards(AuthGuard(), UserRoleGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '👑 Admin/Super-user only route',
    description:
      'Testing endpoint that requires admin or super-user roles. Demonstrates role-based access control.',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Admin route accessed successfully',
    schema: {
      example: {
        ok: true,
        user: {
          id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
          email: 'admin@example.com',
          fullName: 'Admin User',
          isActive: true,
          roles: ['admin'],
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  @ApiResponse({
    status: 403,
    description:
      '🚫 Forbidden - User does not have required role (admin or super-user)',
    schema: {
      example: {
        statusCode: 403,
        message: 'User John Doe need a valid role: [super-user,admin]',
        error: 'Forbidden',
      },
    },
  })
  privateRoute2(@GetUser() user: User) {
    return {
      ok: true,
      user,
    };
  }

  @Get('private3')
  @Auth(ValidRoles.admin)
  @ApiBearerAuth()
  @ApiOperation({
    summary: '🔐 Admin only route (simplified)',
    description:
      'Testing endpoint that requires admin role using the simplified Auth decorator. Demonstrates simplified role-based access control.',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Admin route accessed successfully',
    schema: {
      example: {
        ok: true,
        user: {
          id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
          email: 'admin@example.com',
          fullName: 'Admin User',
          isActive: true,
          roles: ['admin'],
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  @ApiResponse({
    status: 403,
    description: '🚫 Forbidden - User does not have admin role',
    schema: {
      example: {
        statusCode: 403,
        message: 'User John Doe need a valid role: [admin]',
        error: 'Forbidden',
      },
    },
  })
  privateRoute3(@GetUser() user: User) {
    return {
      ok: true,
      user,
    };
  }
}
