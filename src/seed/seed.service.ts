import { Injectable } from '@nestjs/common';
import { Repository, DataSource } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

import { initialData } from './data/seed-data';
import { User } from '../auth/entities/user.entity';
import { People, Contact, Address, ImportantDate } from '../people/entities';

@Injectable()
export class SeedService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,

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

  async runSeed() {
    await this.deleteTables();
    const adminUser = await this.insertUsers();
    await this.insertPeople(adminUser);

    return 'SEED EJECUTADO CORRECTAMENTE - Usuarios y Contactos creados';
  }

  private async deleteTables() {
    // Eliminar registros en orden correcto usando DELETE para evitar problemas con foreign keys
    await this.dataSource.query('DELETE FROM "important_dates"');
    await this.dataSource.query('DELETE FROM "addresses"');
    await this.dataSource.query('DELETE FROM "contacts"');
    await this.dataSource.query('DELETE FROM "people"');
    await this.dataSource.query('DELETE FROM "users"');

    // Opcional: Reiniciar las secuencias de IDs
    await this.dataSource.query(
      'ALTER SEQUENCE "important_dates_id_seq" RESTART WITH 1',
    );
    await this.dataSource.query(
      'ALTER SEQUENCE "addresses_id_seq" RESTART WITH 1',
    );
    await this.dataSource.query(
      'ALTER SEQUENCE "contacts_id_seq" RESTART WITH 1',
    );
  }

  private async insertUsers() {
    const seedUsers = initialData.users;
    const users: User[] = [];

    seedUsers.forEach((user) => {
      users.push(this.userRepository.create(user));
    });

    const dbUsers = await this.userRepository.save(users);
    return dbUsers[0]; // Retorna el primer usuario (admin)
  }

  private async insertPeople(user: User) {
    const seedPeople = initialData.people;
    const insertPromises: Promise<People>[] = [];

    seedPeople.forEach((personData) => {
      insertPromises.push(this.createPerson(personData, user));
    });

    await Promise.all(insertPromises);
    return true;
  }

  private async createPerson(personData: any, user: User): Promise<People> {
    try {
      const {
        contacts = [],
        addresses = [],
        importantDates = [],
        ...peopleDetails
      } = personData;

      // Crear la persona principal primero
      const people = this.peopleRepository.create({
        ...peopleDetails,
        user,
        isTrashed: false,
        isDeleted: false,
      });

      // Guardar el resultado
      const saveResult = await this.peopleRepository.save(people);

      // Manejar ambos casos: array o entidad única
      const savedPeople = Array.isArray(saveResult)
        ? saveResult[0]
        : saveResult;

      // Crear y guardar contactos si existen
      if (contacts.length > 0) {
        const contactEntities = contacts.map((contact: any) =>
          this.contactRepository.create({
            ...contact,
            people: savedPeople,
          }),
        );
        await this.contactRepository.save(contactEntities);
      }

      // Crear y guardar direcciones si existen
      if (addresses.length > 0) {
        const addressEntities = addresses.map((address: any) =>
          this.addressRepository.create({
            ...address,
            people: savedPeople,
          }),
        );
        await this.addressRepository.save(addressEntities);
      }

      // Crear y guardar fechas importantes si existen
      if (importantDates.length > 0) {
        const dateEntities = importantDates.map((date: any) =>
          this.importantDateRepository.create({
            ...date,
            people: savedPeople,
          }),
        );
        await this.importantDateRepository.save(dateEntities);
      }

      // Retornar la persona con todas sus relaciones
      const peopleWithRelations = await this.peopleRepository.findOne({
        where: { id: savedPeople.id },
        relations: ['contacts', 'addresses', 'importantDates'],
      });

      if (!peopleWithRelations) {
        throw new Error(
          `No se pudo encontrar la persona creada con ID: ${savedPeople.id}`,
        );
      }

      return peopleWithRelations;
    } catch (error) {
      console.error('Error creando persona:', error);
      throw error;
    }
  }
}
