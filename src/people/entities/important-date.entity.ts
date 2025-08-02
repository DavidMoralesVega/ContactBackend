import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { People } from './people.entity';

@Entity('important_dates')
export class ImportantDate {
  @ApiProperty({
    example: 1,
    description: 'Important date ID',
  })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({
    example: 15,
    description: 'Day (1-31)',
  })
  @Column('int')
  day: number;

  @ApiProperty({
    example: 6,
    description: 'Month (1-12)',
  })
  @Column('int')
  month: number;

  @ApiProperty({
    example: 1990,
    description: 'Year (1900-2050)',
  })
  @Column('int')
  year: number;

  @ApiProperty({
    example: 'birthday',
    description: 'Date tag (birthday, anniversary, etc.)',
  })
  @Column('text')
  tag: string;

  @ManyToOne(() => People, (people) => people.importantDates, {
    onDelete: 'CASCADE',
  })
  people: People;
}
