import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { AuthModule } from '../auth/auth.module';
import { PeopleService } from './people.service';
import { PeopleController } from './people.controller';
import { People, Contact, Address, ImportantDate } from './entities';

@Module({
  controllers: [PeopleController],
  providers: [PeopleService],
  imports: [
    TypeOrmModule.forFeature([People, Contact, Address, ImportantDate]),
    AuthModule,
  ],
  exports: [PeopleService, TypeOrmModule],
})
export class PeopleModule {}
