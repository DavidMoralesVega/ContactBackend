import { Module } from '@nestjs/common';
import { AuthModule } from './../auth/auth.module';
import { SeedService } from './seed.service';
import { SeedController } from './seed.controller';
import { PeopleModule } from 'src/people/people.module';

@Module({
  controllers: [SeedController],
  providers: [SeedService],
  imports: [AuthModule, PeopleModule],
})
export class SeedModule {}
