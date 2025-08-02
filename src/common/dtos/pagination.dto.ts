import { ApiProperty } from '@nestjs/swagger';

import { Type } from 'class-transformer';
import { IsOptional, IsPositive, Min, IsIn } from 'class-validator';

export class PaginationDto {
  @ApiProperty({
    default: 10,
    description: 'How many rows do you need',
    minimum: 1,
    maximum: 100,
    example: 10,
  })
  @IsOptional()
  @IsPositive()
  @Type(() => Number)
  limit?: number;

  @ApiProperty({
    default: 0,
    description: 'How many rows do you want to skip',
    minimum: 0,
    example: 0,
  })
  @IsOptional()
  @Min(0)
  @Type(() => Number)
  offset?: number;
}

export class PeoplePaginationDto extends PaginationDto {
  @ApiProperty({
    enum: ['name', 'lastName', 'email', 'createdAt', 'updatedAt'],
    default: 'name',
    description: 'Field to sort by',
    example: 'name',
  })
  @IsOptional()
  @IsIn(['name', 'lastName', 'email', 'createdAt', 'updatedAt'])
  sortBy?: 'name' | 'lastName' | 'email' | 'createdAt' | 'updatedAt';

  @ApiProperty({
    enum: ['ASC', 'DESC'],
    default: 'ASC',
    description: 'Sort order (A-Z = ASC, Z-A = DESC)',
    example: 'ASC',
  })
  @IsOptional()
  @IsIn(['ASC', 'DESC'])
  sortOrder?: 'ASC' | 'DESC';
}
