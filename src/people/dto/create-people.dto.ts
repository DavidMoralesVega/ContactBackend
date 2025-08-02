import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsEmail,
  IsOptional,
  IsArray,
  ValidateNested,
  IsInt,
  Min,
  Max,
  Matches,
  MinLength,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateContactDto {
  @ApiProperty({
    example: '+591',
    description: 'Country call code starting with + followed by 1-4 digits',
    pattern: "'^\\+\\d{1,4}",
    minLength: 2,
    maxLength: 5,
  })
  @IsString()
  @Matches(/^\+\d{1,4}$/, {
    message: 'Call code must start with + followed by 1-4 digits',
  })
  callCode: string;

  @ApiProperty({
    example: '12345678',
    description: 'Phone number containing only digits (6-15 characters)',
    pattern: "'^\\d{6,15}",
    minLength: 6,
    maxLength: 15,
  })
  @IsString()
  @Matches(/^\d{6,15}$/, {
    message: 'Number must contain only digits and be between 6-15 characters',
  })
  number: string;

  @ApiProperty({
    example: 'mobile',
    description: 'Contact tag (free text): mobile, home, work, personal, etc.',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  tag: string;
}

export class CreateAddressDto {
  @ApiProperty({
    example: 'Av. Siempre Viva',
    description: 'Street name',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  street: string;

  @ApiProperty({
    example: '123',
    description: 'Street number or apartment/house identifier',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  number: string;

  @ApiProperty({
    example: 'Springfield, USA',
    description: 'City, state, country or complete location',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  location: string;

  @ApiProperty({
    example: 'home',
    description: 'Address tag (free text): home, work, office, vacation, etc.',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  tag: string;
}

export class CreateImportantDateDto {
  @ApiProperty({
    example: 15,
    description: 'Day of the month (1-31)',
    minimum: 1,
    maximum: 31,
  })
  @IsInt()
  @Min(1)
  @Max(31)
  day: number;

  @ApiProperty({
    example: 6,
    description: 'Month of the year (1-12)',
    minimum: 1,
    maximum: 12,
  })
  @IsInt()
  @Min(1)
  @Max(12)
  month: number;

  @ApiProperty({
    example: 1990,
    description: 'Year (valid range: 1900-2050)',
    minimum: 1900,
    maximum: 2050,
  })
  @IsInt()
  @Min(1900)
  @Max(2050)
  year: number;

  @ApiProperty({
    example: 'birthday',
    description:
      'Date tag (free text): birthday, anniversary, graduation, wedding, etc.',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  tag: string;
}

export class CreatePeopleDto {
  @ApiProperty({
    example: 'John',
    description: 'First name of the contact',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  name: string;

  @ApiProperty({
    example: 'Doe',
    description: 'Last name of the contact',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  lastName: string;

  @ApiProperty({
    example: 'john.doe@email.com',
    description:
      'Email address (optional). Must be a valid email format if provided.',
    required: false,
    format: 'email',
  })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiProperty({
    example: 'http://localhost:3000/api/files/people/uuid-filename.jpg',
    description:
      'Photo URL (optional). Use POST /api/files/people to upload a photo first.',
    required: false,
    format: 'uri',
  })
  @IsOptional()
  @IsString()
  photo?: string;

  @ApiProperty({
    description:
      'Array of contact phone numbers (optional). You can add multiple phone numbers with different tags.',
    type: [CreateContactDto],
    required: false,
    example: [
      {
        callCode: '+591',
        number: '12345678',
        tag: 'mobile',
      },
      {
        callCode: '+591',
        number: '87654321',
        tag: 'work',
      },
    ],
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateContactDto)
  contacts?: CreateContactDto[];

  @ApiProperty({
    description:
      'Array of addresses (optional). You can add multiple addresses with different tags.',
    type: [CreateAddressDto],
    required: false,
    example: [
      {
        street: 'Av. Siempre Viva',
        number: '123',
        location: 'La Paz, Bolivia',
        tag: 'home',
      },
      {
        street: 'Calle Comercio',
        number: '456',
        location: 'Santa Cruz, Bolivia',
        tag: 'work',
      },
    ],
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateAddressDto)
  addresses?: CreateAddressDto[];

  @ApiProperty({
    description:
      'Array of important dates (optional). You can add birthdays, anniversaries, and other significant dates.',
    type: [CreateImportantDateDto],
    required: false,
    example: [
      {
        day: 15,
        month: 6,
        year: 1990,
        tag: 'birthday',
      },
      {
        day: 20,
        month: 12,
        year: 2015,
        tag: 'wedding anniversary',
      },
    ],
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateImportantDateDto)
  importantDates?: CreateImportantDateDto[];
}
