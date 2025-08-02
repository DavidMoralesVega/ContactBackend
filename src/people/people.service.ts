import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { validate as isUUID } from 'uuid';

import { People, Contact, Address, ImportantDate } from './entities';
import { CreatePeopleDto } from './dto/create-people.dto';
import { UpdatePeopleDto } from './dto/update-people.dto';
import { PeoplePaginationDto } from '../common/dtos/pagination.dto';
import { User } from '../auth/entities/user.entity';

@Injectable()
export class PeopleService {
  private readonly logger = new Logger('PeopleService');

  constructor(
    @InjectRepository(People)
    private readonly peopleRepository: Repository<People>,

    @InjectRepository(Contact)
    private readonly contactRepository: Repository<Contact>,

    @InjectRepository(Address)
    private readonly addressRepository: Repository<Address>,

    @InjectRepository(ImportantDate)
    private readonly importantDateRepository: Repository<ImportantDate>,

    private readonly dataSource: DataSource,
  ) {}

  async create(createPeopleDto: CreatePeopleDto, user: User) {
    try {
      const {
        contacts = [],
        addresses = [],
        importantDates = [],
        ...peopleDetails
      } = createPeopleDto;

      const people = this.peopleRepository.create({
        ...peopleDetails,
        contacts: contacts.map((contact) =>
          this.contactRepository.create(contact),
        ),
        addresses: addresses.map((address) =>
          this.addressRepository.create(address),
        ),
        importantDates: importantDates.map((date) =>
          this.importantDateRepository.create(date),
        ),
        user,
      });

      await this.peopleRepository.save(people);
      return people;
    } catch (error) {
      this.handleDBExceptions(error);
    }
  }

  async findAll(paginationDto: PeoplePaginationDto, user: User) {
    const {
      limit = 10,
      offset = 0,
      sortBy = 'name',
      sortOrder = 'ASC',
    } = paginationDto;

    const people = await this.peopleRepository.find({
      take: limit,
      skip: offset,
      where: {
        user: { id: user.id },
        isTrashed: false,
        isDeleted: false,
      },
      relations: ['contacts', 'addresses', 'importantDates'],
      order: {
        [sortBy]: sortOrder,
      },
    });

    return people;
  }

  async findAllTrashed(paginationDto: PeoplePaginationDto, user: User) {
    const {
      limit = 10,
      offset = 0,
      sortBy = 'updatedAt',
      sortOrder = 'DESC',
    } = paginationDto;

    const people = await this.peopleRepository.find({
      take: limit,
      skip: offset,
      where: {
        user: { id: user.id },
        isTrashed: true,
        isDeleted: false,
      },
      relations: ['contacts', 'addresses', 'importantDates'],
      order: {
        [sortBy]: sortOrder,
      },
    });

    return people;
  }

  async findOne(term: string, user: User) {
    let people: People | null = null;

    if (isUUID(term)) {
      people = await this.peopleRepository.findOne({
        where: {
          id: term,
          user: { id: user.id },
          isDeleted: false,
        },
        relations: ['contacts', 'addresses', 'importantDates'],
      });
    } else {
      const queryBuilder = this.peopleRepository.createQueryBuilder('people');
      people = await queryBuilder
        .where(
          '(UPPER(people.name) LIKE :term OR UPPER(people.lastName) LIKE :term OR UPPER(people.email) LIKE :term)',
          {
            term: `%${term.toUpperCase()}%`,
          },
        )
        .andWhere('people.userId = :userId', { userId: user.id })
        .andWhere('people.isDeleted = :isDeleted', { isDeleted: false })
        .leftJoinAndSelect('people.contacts', 'contacts')
        .leftJoinAndSelect('people.addresses', 'addresses')
        .leftJoinAndSelect('people.importantDates', 'importantDates')
        .getOne();
    }

    if (!people) {
      throw new NotFoundException(`Person with "${term}" not found`);
    }

    return people;
  }

  async update(id: string, updatePeopleDto: UpdatePeopleDto, user: User) {
    const { contacts, addresses, importantDates, ...toUpdate } =
      updatePeopleDto;

    // First, verify the person exists and belongs to the user
    const existingPeople = await this.findOne(id, user);

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Update main people data
      const people = await queryRunner.manager.preload(People, {
        id,
        ...toUpdate,
      });

      if (!people) {
        throw new NotFoundException(`Person with id: ${id} not found`);
      }

      // Update related entities if provided
      if (contacts) {
        await queryRunner.manager.delete(Contact, { people: { id } });
        people.contacts = contacts.map((contact) =>
          this.contactRepository.create(contact),
        );
      }

      if (addresses) {
        await queryRunner.manager.delete(Address, { people: { id } });
        people.addresses = addresses.map((address) =>
          this.addressRepository.create(address),
        );
      }

      if (importantDates) {
        await queryRunner.manager.delete(ImportantDate, { people: { id } });
        people.importantDates = importantDates.map((date) =>
          this.importantDateRepository.create(date),
        );
      }

      people.user = user;
      await queryRunner.manager.save(people);

      await queryRunner.commitTransaction();

      return this.findOne(id, user);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.handleDBExceptions(error);
    } finally {
      await queryRunner.release();
    }
  }

  async moveToTrash(id: string, user: User) {
    const people = await this.findOne(id, user);

    if (people.isTrashed) {
      throw new BadRequestException('Person is already in trash');
    }

    people.isTrashed = true;
    await this.peopleRepository.save(people);

    return { message: 'Person moved to trash successfully' };
  }

  async restoreFromTrash(id: string, user: User) {
    const people = await this.peopleRepository.findOne({
      where: {
        id,
        user: { id: user.id },
        isTrashed: true,
        isDeleted: false,
      },
    });

    if (!people) {
      throw new NotFoundException('Person not found in trash');
    }

    people.isTrashed = false;
    await this.peopleRepository.save(people);

    return { message: 'Person restored successfully' };
  }

  async remove(id: string, user: User) {
    const people = await this.peopleRepository.findOne({
      where: {
        id,
        user: { id: user.id },
        isTrashed: true,
        isDeleted: false,
      },
    });

    if (!people) {
      throw new NotFoundException(
        'Person not found in trash or already deleted',
      );
    }

    people.isDeleted = true;
    await this.peopleRepository.save(people);

    return { message: 'Person permanently deleted' };
  }

  private handleDBExceptions(error: any): never {
    if (error.code === '23505') {
      throw new BadRequestException(error.detail);
    }

    this.logger.error(error);
    throw new InternalServerErrorException(
      'Unexpected error, check server logs',
    );
  }
}
