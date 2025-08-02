import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { People } from './people.entity';

@Entity('addresses')
export class Address {
  @ApiProperty({
    example: 1,
    description: 'Address ID',
  })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({
    example: 'Av. Siempre Viva',
    description: 'Street name',
  })
  @Column('text')
  street: string;

  @ApiProperty({
    example: '123',
    description: 'Street number',
  })
  @Column('text')
  number: string;

  @ApiProperty({
    example: 'Springfield, USA',
    description: 'Location/City',
  })
  @Column('text')
  location: string;

  @ApiProperty({
    example: 'home',
    description: 'Address tag (home, work, etc.)',
  })
  @Column('text')
  tag: string;

  @ManyToOne(() => People, (people) => people.addresses, {
    onDelete: 'CASCADE',
  })
  people: People;
}
