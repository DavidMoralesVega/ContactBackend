import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import {
  ApiResponse,
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';

import { PeopleService } from './people.service';
import { CreatePeopleDto } from './dto/create-people.dto';
import { UpdatePeopleDto } from './dto/update-people.dto';
import { PeoplePaginationDto } from '../common/dtos/pagination.dto';
import { Auth, GetUser } from '../auth/decorators';
import { User } from '../auth/entities/user.entity';
import { People } from './entities/people.entity';
import { ParseUUIDPipe, Query } from '@nestjs/common';

@ApiTags('👥 People - Contact Management')
@ApiBearerAuth()
@Controller('people')
@Auth() // All endpoints require authentication
export class PeopleController {
  constructor(private readonly peopleService: PeopleService) {}

  @Post()
  @ApiOperation({
    summary: '👤 Create a new contact',
    description:
      'Creates a new contact with all associated information (phone numbers, addresses, important dates). Similar to adding a contact in Google Contacts.',
  })
  @ApiResponse({
    status: 201,
    description: '✅ Contact was created successfully',
    type: People,
    schema: {
      example: {
        id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
        name: 'Juan',
        lastName: 'Pérez',
        email: 'juan.perez@email.com',
        photo: 'http://localhost:3000/api/files/people/uuid-filename.jpg',
        contacts: [
          {
            id: 1,
            callCode: '+591',
            number: '12345678',
            tag: 'mobile',
          },
        ],
        addresses: [
          {
            id: 1,
            street: 'Av. Siempre Viva',
            number: '123',
            location: 'La Paz, Bolivia',
            tag: 'home',
          },
        ],
        importantDates: [
          {
            id: 1,
            day: 15,
            month: 6,
            year: 1990,
            tag: 'birthday',
          },
        ],
        isTrashed: false,
        isDeleted: false,
        createdAt: '2025-01-15T10:30:00Z',
        updatedAt: '2025-01-15T10:30:00Z',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '❌ Bad request - Validation errors',
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  @ApiResponse({
    status: 403,
    description: '🚫 Forbidden - Token related issue',
  })
  create(@Body() createPeopleDto: CreatePeopleDto, @GetUser() user: User) {
    return this.peopleService.create(createPeopleDto, user);
  }

  @Get()
  @ApiOperation({
    summary: '📋 Get all active contacts',
    description:
      'Retrieves a paginated list of all active contacts (not in trash) for the authenticated user. Supports sorting A-Z or Z-A by different fields.',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Number of contacts to return (1-100)',
    example: 10,
  })
  @ApiQuery({
    name: 'offset',
    required: false,
    type: Number,
    description: 'Number of contacts to skip',
    example: 0,
  })
  @ApiQuery({
    name: 'sortBy',
    required: false,
    enum: ['name', 'lastName', 'email', 'createdAt', 'updatedAt'],
    description: 'Field to sort by',
    example: 'name',
  })
  @ApiQuery({
    name: 'sortOrder',
    required: false,
    enum: ['ASC', 'DESC'],
    description: 'Sort order: ASC (A-Z) or DESC (Z-A)',
    example: 'ASC',
  })
  @ApiResponse({
    status: 200,
    description: '✅ List of active contacts retrieved successfully',
    type: [People],
    schema: {
      example: [
        {
          id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
          name: 'Ana',
          lastName: 'García',
          email: 'ana.garcia@email.com',
          photo: null,
          contacts: [],
          addresses: [],
          importantDates: [],
          isTrashed: false,
          isDeleted: false,
          createdAt: '2025-01-15T10:30:00Z',
          updatedAt: '2025-01-15T10:30:00Z',
        },
      ],
    },
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  findAll(@Query() paginationDto: PeoplePaginationDto, @GetUser() user: User) {
    console.log('Fetching all contacts with pagination:', user);

    return this.peopleService.findAll(paginationDto, user);
  }

  @Get('trash')
  @ApiOperation({
    summary: '🗑️ Get contacts in trash',
    description:
      'Retrieves a paginated list of contacts that have been moved to trash but not permanently deleted. These contacts can be restored.',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Number of contacts to return',
    example: 10,
  })
  @ApiQuery({
    name: 'offset',
    required: false,
    type: Number,
    description: 'Number of contacts to skip',
    example: 0,
  })
  @ApiQuery({
    name: 'sortBy',
    required: false,
    enum: ['name', 'lastName', 'email', 'createdAt', 'updatedAt'],
    description: 'Field to sort by',
    example: 'updatedAt',
  })
  @ApiQuery({
    name: 'sortOrder',
    required: false,
    enum: ['ASC', 'DESC'],
    description: 'Sort order',
    example: 'DESC',
  })
  @ApiResponse({
    status: 200,
    description: '✅ List of trashed contacts retrieved successfully',
    type: [People],
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  findAllTrashed(
    @Query() paginationDto: PeoplePaginationDto,
    @GetUser() user: User,
  ) {
    return this.peopleService.findAllTrashed(paginationDto, user);
  }

  @Get(':term')
  @ApiOperation({
    summary: '🔍 Find a specific contact',
    description:
      'Searches for a contact by ID (UUID), name, lastName, or email. Returns the complete contact information including all related data.',
  })
  @ApiParam({
    name: 'term',
    description: 'Search term: can be UUID, name, lastName, or email',
    example: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Contact found successfully',
    type: People,
    schema: {
      example: {
        id: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
        name: 'Juan',
        lastName: 'Pérez',
        email: 'juan.perez@email.com',
        photo: 'http://localhost:3000/api/files/people/uuid-filename.jpg',
        contacts: [
          {
            id: 1,
            callCode: '+591',
            number: '12345678',
            tag: 'mobile',
          },
        ],
        addresses: [
          {
            id: 1,
            street: 'Av. Siempre Viva',
            number: '123',
            location: 'La Paz, Bolivia',
            tag: 'home',
          },
        ],
        importantDates: [
          {
            id: 1,
            day: 15,
            month: 6,
            year: 1990,
            tag: 'birthday',
          },
        ],
        isTrashed: false,
        isDeleted: false,
        createdAt: '2025-01-15T10:30:00Z',
        updatedAt: '2025-01-15T10:30:00Z',
      },
    },
  })
  @ApiResponse({ status: 404, description: '❌ Contact not found' })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  findOne(@Param('term') term: string, @GetUser() user: User) {
    return this.peopleService.findOne(term, user);
  }

  @Patch(':id')
  @ApiOperation({
    summary: '✏️ Update a contact',
    description:
      'Updates an existing contact. You can update any field including adding/removing phone numbers, addresses, and important dates. Partial updates are supported.',
  })
  @ApiParam({
    name: 'id',
    description: 'UUID of the contact to update',
    example: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Contact was updated successfully',
    type: People,
  })
  @ApiResponse({
    status: 400,
    description: '❌ Bad request - Validation errors',
  })
  @ApiResponse({ status: 404, description: '❌ Contact not found' })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updatePeopleDto: UpdatePeopleDto,
    @GetUser() user: User,
  ) {
    return this.peopleService.update(id, updatePeopleDto, user);
  }

  @Delete(':id')
  @ApiOperation({
    summary: '🗑️ Move contact to trash',
    description:
      'Moves a contact to trash (soft delete). The contact will no longer appear in the main list but can be restored later. This is the first step in the deletion process.',
  })
  @ApiParam({
    name: 'id',
    description: 'UUID of the contact to move to trash',
    example: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Contact moved to trash successfully',
    schema: {
      example: {
        message: 'Person moved to trash successfully',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '❌ Bad request - Contact is already in trash',
  })
  @ApiResponse({ status: 404, description: '❌ Contact not found' })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  moveToTrash(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: User) {
    return this.peopleService.moveToTrash(id, user);
  }

  @Post(':id/restore')
  @ApiOperation({
    summary: '♻️ Restore contact from trash',
    description:
      'Restores a contact from trash back to the active contacts list. The contact will appear in the main list again.',
  })
  @ApiParam({
    name: 'id',
    description: 'UUID of the contact to restore from trash',
    example: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Contact restored from trash successfully',
    schema: {
      example: {
        message: 'Person restored successfully',
      },
    },
  })
  @ApiResponse({ status: 404, description: '❌ Contact not found in trash' })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  restoreFromTrash(
    @Param('id', ParseUUIDPipe) id: string,
    @GetUser() user: User,
  ) {
    return this.peopleService.restoreFromTrash(id, user);
  }

  @Delete(':id/permanent')
  @ApiOperation({
    summary: '💀 Permanently delete contact',
    description:
      '⚠️ DANGER: Permanently deletes a contact from trash. This action cannot be undone! The contact must be in trash before permanent deletion.',
  })
  @ApiParam({
    name: 'id',
    description: 'UUID of the contact to permanently delete',
    example: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Contact permanently deleted',
    schema: {
      example: {
        message: 'Person permanently deleted',
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: '❌ Contact not found in trash or already deleted',
  })
  @ApiResponse({
    status: 401,
    description: '🔒 Unauthorized - Invalid or missing token',
  })
  remove(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: User) {
    return this.peopleService.remove(id, user);
  }
}
