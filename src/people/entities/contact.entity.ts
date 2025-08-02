import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { People } from './people.entity';

@Entity('contacts')
export class Contact {
  @ApiProperty({
    example: 1,
    description: 'Contact ID',
  })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({
    example: '+591',
    description: 'Country call code',
  })
  @Column('text')
  callCode: string;

  @ApiProperty({
    example: '12345678',
    description: 'Phone number',
  })
  @Column('text')
  number: string;

  @ApiProperty({
    example: 'mobile',
    description: 'Contact tag (mobile, home, work, etc.)',
  })
  @Column('text')
  tag: string;

  @ManyToOne(() => People, (people) => people.contacts, { onDelete: 'CASCADE' })
  people: People;
}
