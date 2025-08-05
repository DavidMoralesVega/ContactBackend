import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ApiHideProperty, ApiProperty } from '@nestjs/swagger';
import { User } from '../../auth/entities/user.entity';
import { Contact } from './contact.entity';
import { Address } from './address.entity';
import { ImportantDate } from './important-date.entity';

@Entity('people')
export class People {
  @ApiProperty({
    example: 'cd533345-f1f3-48c9-a62e-7dc2da50c8f8',
    description: 'People ID',
    uniqueItems: true,
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({
    example: 'John',
    description: 'First name',
  })
  @Column('text')
  name: string;

  @ApiProperty({
    example: 'Doe',
    description: 'Last name',
  })
  @Column('text')
  lastName: string;

  @ApiProperty({
    example: 'john.doe@email.com',
    description: 'Email address',
  })
  @Column('text', {
    nullable: true,
  })
  email?: string;

  @ApiProperty({
    example: 'https://example.com/photo.jpg',
    description: 'Photo URL',
  })
  @Column('text', {
    nullable: true,
  })
  photo?: string;

  @ApiProperty({
    description: 'Contact information',
  })
  @OneToMany(() => Contact, (contact) => contact.people, {
    cascade: true,
    eager: true,
  })
  contacts: Contact[];

  @ApiProperty({
    description: 'Addresses',
  })
  @OneToMany(() => Address, (address) => address.people, {
    cascade: true,
    eager: true,
  })
  addresses: Address[];

  @ApiProperty({
    description: 'Important dates',
  })
  @OneToMany(() => ImportantDate, (importantDate) => importantDate.people, {
    cascade: true,
    eager: true,
  })
  importantDates: ImportantDate[];

  @ApiHideProperty()
  @ManyToOne(() => User, (user) => user.people, { eager: true })
  user: User;

  @ApiProperty({
    description: 'Is in trash',
  })
  @Column('boolean', {
    default: false,
  })
  isTrashed: boolean;

  @ApiProperty({
    description: 'Is permanently deleted',
  })
  @Column('boolean', {
    default: false,
  })
  isDeleted: boolean;

  @ApiProperty({
    description: 'Creation date',
  })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({
    description: 'Last update date',
  })
  @UpdateDateColumn()
  updatedAt: Date;
}
