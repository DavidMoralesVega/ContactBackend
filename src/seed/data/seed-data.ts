import * as bcrypt from 'bcrypt';

interface SeedUser {
  email: string;
  fullName: string;
  password: string;
  roles: string[];
}

interface SeedContact {
  callCode: string;
  number: string;
  tag: string;
}

interface SeedAddress {
  street: string;
  number: string;
  location: string;
  tag: string;
}

interface SeedImportantDate {
  day: number;
  month: number;
  year: number;
  tag: string;
}

interface SeedPeople {
  name: string;
  lastName: string;
  email?: string;
  photo?: string;
  contacts?: SeedContact[];
  addresses?: SeedAddress[];
  importantDates?: SeedImportantDate[];
}

interface SeedData {
  users: SeedUser[];
  people: SeedPeople[];
}

export const initialData: SeedData = {
  users: [
    {
      email: 'admin@contactapp.com',
      fullName: 'Administrador Principal',
      password: bcrypt.hashSync('Admin123', 10),
      roles: ['admin'],
    },
    {
      email: 'usuario@contactapp.com',
      fullName: 'Usuario Normal',
      password: bcrypt.hashSync('User123', 10),
      roles: ['user'],
    },
  ],

  people: [
    {
      name: 'María',
      lastName: 'González Pérez',
      email: 'maria.gonzalez@email.com',
      contacts: [
        { callCode: '+591', number: '70123456', tag: 'móvil' },
        { callCode: '+591', number: '22345678', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Av. 16 de Julio',
          number: '1234',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 15, month: 3, year: 1985, tag: 'cumpleaños' },
        { day: 14, month: 2, year: 2010, tag: 'aniversario' },
      ],
    },
    {
      name: 'Juan Carlos',
      lastName: 'Mamani Quispe',
      email: 'juan.mamani@empresa.com',
      contacts: [
        { callCode: '+591', number: '75987654', tag: 'móvil' },
        { callCode: '+591', number: '24567890', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Calle Comercio',
          number: '567',
          location: 'El Alto, Bolivia',
          tag: 'casa',
        },
        {
          street: 'Av. Blanco Galindo',
          number: '890',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
      ],
      importantDates: [{ day: 22, month: 8, year: 1978, tag: 'cumpleaños' }],
    },
    {
      name: 'Ana Lucía',
      lastName: 'Vargas Mendoza',
      email: 'ana.vargas@gmail.com',
      contacts: [{ callCode: '+591', number: '69876543', tag: 'móvil' }],
      addresses: [
        {
          street: 'Av. Cristo Redentor',
          number: '234',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 5, month: 12, year: 1992, tag: 'cumpleaños' },
        { day: 25, month: 7, year: 2018, tag: 'graduación' },
      ],
    },
    {
      name: 'Roberto',
      lastName: 'Choque Silva',
      email: 'roberto.choque@hotmail.com',
      contacts: [
        { callCode: '+591', number: '78654321', tag: 'móvil' },
        { callCode: '+591', number: '64123456', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Calle Murillo',
          number: '456',
          location: 'Oruro, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 10, month: 6, year: 1980, tag: 'cumpleaños' },
        { day: 30, month: 11, year: 2005, tag: 'boda' },
      ],
    },
    {
      name: 'Carmen Rosa',
      lastName: 'Flores Gutiérrez',
      email: 'carmen.flores@yahoo.com',
      contacts: [
        { callCode: '+591', number: '65432109', tag: 'móvil' },
        { callCode: '+591', number: '23456789', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Av. América',
          number: '789',
          location: 'Sucre, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 18, month: 4, year: 1987, tag: 'cumpleaños' }],
    },
    {
      name: 'Luis Fernando',
      lastName: 'Morales López',
      email: 'luis.morales@empresa.bo',
      contacts: [
        { callCode: '+591', number: '71234567', tag: 'móvil' },
        { callCode: '+591', number: '25678901', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Calle Bolívar',
          number: '123',
          location: 'Potosí, Bolivia',
          tag: 'casa',
        },
        {
          street: 'Av. Arce',
          number: '456',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
      ],
      importantDates: [
        { day: 7, month: 9, year: 1983, tag: 'cumpleaños' },
        { day: 15, month: 1, year: 2012, tag: 'aniversario laboral' },
      ],
    },
    {
      name: 'Patricia',
      lastName: 'Ríos Herrera',
      email: 'patricia.rios@outlook.com',
      contacts: [{ callCode: '+591', number: '67890123', tag: 'móvil' }],
      addresses: [
        {
          street: 'Av. Hernando Siles',
          number: '890',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 12, month: 11, year: 1990, tag: 'cumpleaños' },
        { day: 8, month: 3, year: 2020, tag: 'día de la mujer' },
      ],
    },
    {
      name: 'Carlos Alberto',
      lastName: 'Ticona Mamani',
      email: 'carlos.ticona@gmail.com',
      contacts: [
        { callCode: '+591', number: '76543210', tag: 'móvil' },
        { callCode: '+591', number: '26789012', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Calle Sagárnaga',
          number: '345',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 25, month: 12, year: 1975, tag: 'cumpleaños' },
        { day: 6, month: 8, year: 1825, tag: 'día de la independencia' },
      ],
    },
    {
      name: 'Silvia',
      lastName: 'Condori Apaza',
      email: 'silvia.condori@hotmail.com',
      contacts: [
        { callCode: '+591', number: '65789012', tag: 'móvil' },
        { callCode: '+591', number: '27890123', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Max Paredes',
          number: '678',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 20, month: 1, year: 1988, tag: 'cumpleaños' }],
    },
    {
      name: 'Fernando',
      lastName: 'Gutierrez Rojas',
      email: 'fernando.gutierrez@empresa.com',
      contacts: [
        { callCode: '+591', number: '72345678', tag: 'móvil' },
        { callCode: '+591', number: '64567890', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Calle Jaén',
          number: '234',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
        {
          street: 'Av. 6 de Agosto',
          number: '567',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
      ],
      importantDates: [
        { day: 3, month: 7, year: 1982, tag: 'cumpleaños' },
        { day: 1, month: 5, year: 2015, tag: 'día del trabajador' },
      ],
    },
    {
      name: 'Mónica',
      lastName: 'Quiroga Mendez',
      email: 'monica.quiroga@yahoo.com',
      contacts: [{ callCode: '+591', number: '68901234', tag: 'móvil' }],
      addresses: [
        {
          street: 'Av. Ballivián',
          number: '901',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 14, month: 2, year: 1993, tag: 'cumpleaños' },
        { day: 14, month: 2, year: 2023, tag: 'día de san valentín' },
      ],
    },
    {
      name: 'Andrés',
      lastName: 'Sánchez Velasco',
      email: 'andres.sanchez@gmail.com',
      contacts: [
        { callCode: '+591', number: '79012345', tag: 'móvil' },
        { callCode: '+591', number: '28901234', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Calle Linares',
          number: '456',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 16, month: 10, year: 1979, tag: 'cumpleaños' }],
    },
    {
      name: 'Rosario',
      lastName: 'Huanca Torres',
      email: 'rosario.huanca@outlook.com',
      contacts: [
        { callCode: '+591', number: '66789123', tag: 'móvil' },
        { callCode: '+591', number: '23789456', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Juan Pablo II',
          number: '123',
          location: 'El Alto, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 7, month: 10, year: 1986, tag: 'cumpleaños' },
        { day: 12, month: 10, year: 1492, tag: 'día de la raza' },
      ],
    },
    {
      name: 'Miguel',
      lastName: 'Callisaya Nina',
      email: 'miguel.callisaya@hotmail.com',
      contacts: [{ callCode: '+591', number: '74567890', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Potosí',
          number: '789',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 29, month: 5, year: 1984, tag: 'cumpleaños' }],
    },
    {
      name: 'Elena',
      lastName: 'Castro Jiménez',
      email: 'elena.castro@empresa.bo',
      contacts: [
        { callCode: '+591', number: '63456789', tag: 'móvil' },
        { callCode: '+591', number: '24567890', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Av. Mariscal Santa Cruz',
          number: '345',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Illampu',
          number: '678',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 21, month: 3, year: 1991, tag: 'cumpleaños' },
        { day: 21, month: 6, year: 2021, tag: 'año nuevo aymara' },
      ],
    },
    {
      name: 'Jorge',
      lastName: 'Poma Carvajal',
      email: 'jorge.poma@gmail.com',
      contacts: [
        { callCode: '+591', number: '75678901', tag: 'móvil' },
        { callCode: '+591', number: '29012345', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Av. Costanera',
          number: '234',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 4, month: 11, year: 1977, tag: 'cumpleaños' }],
    },
    {
      name: 'Verónica',
      lastName: 'Alanoca Quisbert',
      email: 'veronica.alanoca@yahoo.com',
      contacts: [{ callCode: '+591', number: '69789012', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Sucre',
          number: '567',
          location: 'Tarija, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 8, month: 12, year: 1989, tag: 'cumpleaños' },
        { day: 8, month: 12, year: 1989, tag: 'inmaculada concepción' },
      ],
    },
    {
      name: 'Ricardo',
      lastName: 'Vásquez Paredes',
      email: 'ricardo.vasquez@hotmail.com',
      contacts: [
        { callCode: '+591', number: '77890123', tag: 'móvil' },
        { callCode: '+591', number: '65432198', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Las Americas',
          number: '890',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
        {
          street: 'Calle 21 de Mayo',
          number: '123',
          location: 'Santa Cruz, Bolivia',
          tag: 'oficina',
        },
      ],
      importantDates: [
        { day: 13, month: 4, year: 1981, tag: 'cumpleaños' },
        { day: 21, month: 5, year: 2010, tag: 'aniversario' },
      ],
    },
    {
      name: 'Gloria',
      lastName: 'Zenteno Aguilar',
      email: 'gloria.zenteno@outlook.com',
      contacts: [
        { callCode: '+591', number: '62345678', tag: 'móvil' },
        { callCode: '+591', number: '25678901', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Calle Ayacucho',
          number: '456',
          location: 'Sucre, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 24, month: 9, year: 1994, tag: 'cumpleaños' },
        { day: 24, month: 9, year: 1994, tag: 'día de la primavera' },
      ],
    },
    {
      name: 'Ramiro',
      lastName: 'Choquehuanca Cruz',
      email: 'ramiro.choquehuanca@empresa.com',
      contacts: [
        { callCode: '+591', number: '78123456', tag: 'móvil' },
        { callCode: '+591', number: '64789012', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Circunvalación',
          number: '789',
          location: 'Trinidad, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 11, month: 1, year: 1976, tag: 'cumpleaños' },
        { day: 22, month: 1, year: 2006, tag: 'día del estado plurinacional' },
      ],
    },
    {
      name: 'Alejandro',
      lastName: 'Bustamante Rocha',
      email: 'alejandro.bustamante@gmail.com',
      contacts: [
        { callCode: '+591', number: '73456789', tag: 'móvil' },
        { callCode: '+591', number: '26543210', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Calle Rosendo Gutiérrez',
          number: '567',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 2, month: 2, year: 1986, tag: 'cumpleaños' },
        { day: 2, month: 2, year: 2020, tag: 'día de la candelaria' },
      ],
    },
    {
      name: 'Beatriz',
      lastName: 'Limachi Condori',
      email: 'beatriz.limachi@outlook.com',
      contacts: [{ callCode: '+591', number: '61234567', tag: 'móvil' }],
      addresses: [
        {
          street: 'Av. Petrolera',
          number: '1234',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 9, month: 5, year: 1995, tag: 'cumpleaños' }],
    },
    {
      name: 'Diego',
      lastName: 'Espinoza Martínez',
      email: 'diego.espinoza@empresa.bo',
      contacts: [
        { callCode: '+591', number: '74321098', tag: 'móvil' },
        { callCode: '+591', number: '44567890', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Oquendo',
          number: '890',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
        {
          street: 'Calle España',
          number: '234',
          location: 'Cochabamba, Bolivia',
          tag: 'oficina',
        },
      ],
      importantDates: [
        { day: 17, month: 7, year: 1989, tag: 'cumpleaños' },
        { day: 14, month: 9, year: 2016, tag: 'día de cochabamba' },
      ],
    },
    {
      name: 'Esperanza',
      lastName: 'Yapita Colque',
      email: 'esperanza.yapita@hotmail.com',
      contacts: [
        { callCode: '+591', number: '68765432', tag: 'móvil' },
        { callCode: '+591', number: '22876543', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Calle Evaristo Valle',
          number: '345',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 28, month: 8, year: 1972, tag: 'cumpleaños' },
        { day: 1, month: 11, year: 2000, tag: 'día de todos los santos' },
      ],
    },
    {
      name: 'Francisco',
      lastName: 'Mamani Chura',
      email: 'francisco.mamani@yahoo.com',
      contacts: [{ callCode: '+591', number: '77654321', tag: 'móvil' }],
      addresses: [
        {
          street: 'Av. Montes',
          number: '678',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 4, month: 10, year: 1984, tag: 'cumpleaños' },
        { day: 4, month: 10, year: 1984, tag: 'día de san francisco' },
      ],
    },
    {
      name: 'Gabriela',
      lastName: 'Quispe Mamani',
      email: 'gabriela.quispe@gmail.com',
      contacts: [
        { callCode: '+591', number: '65987654', tag: 'móvil' },
        { callCode: '+591', number: '42345678', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Aroma',
          number: '456',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 31, month: 12, year: 1991, tag: 'cumpleaños' },
        { day: 31, month: 12, year: 2019, tag: 'año nuevo' },
      ],
    },
    {
      name: 'Hernán',
      lastName: 'Vargas Soliz',
      email: 'hernan.vargas@empresa.com',
      contacts: [
        { callCode: '+591', number: '79876543', tag: 'móvil' },
        { callCode: '+591', number: '33456789', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Av. Banzer',
          number: '789',
          location: 'Santa Cruz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Barrio Las Palmas',
          number: '123',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 6, month: 1, year: 1987, tag: 'cumpleaños' },
        { day: 6, month: 1, year: 2018, tag: 'día de reyes' },
      ],
    },
    {
      name: 'Isabel',
      lastName: 'Cáceres Mendoza',
      email: 'isabel.caceres@outlook.com',
      contacts: [{ callCode: '+591', number: '62876543', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Dalence',
          number: '567',
          location: 'Sucre, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 25, month: 5, year: 1993, tag: 'cumpleaños' },
        { day: 25, month: 5, year: 1809, tag: 'revolución de chuquisaca' },
      ],
    },
    {
      name: 'Javier',
      lastName: 'Torrez Ramírez',
      email: 'javier.torrez@hotmail.com',
      contacts: [
        { callCode: '+591', number: '71876543', tag: 'móvil' },
        { callCode: '+591', number: '62543210', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Circunvalación',
          number: '234',
          location: 'Tarija, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 15, month: 4, year: 1980, tag: 'cumpleaños' },
        { day: 15, month: 4, year: 2012, tag: 'aniversario' },
      ],
    },
    {
      name: 'Karina',
      lastName: 'Llanos Pérez',
      email: 'karina.llanos@gmail.com',
      contacts: [
        { callCode: '+591', number: '67543210', tag: 'móvil' },
        { callCode: '+591', number: '46789012', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Av. Heroínas',
          number: '890',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 27, month: 5, year: 1988, tag: 'cumpleaños' },
        { day: 27, month: 5, year: 1812, tag: 'día de las heroínas' },
      ],
    },
    {
      name: 'Lorenzo',
      lastName: 'Chambi Quisbert',
      email: 'lorenzo.chambi@yahoo.com',
      contacts: [{ callCode: '+591', number: '78321098', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Quijarro',
          number: '345',
          location: 'Potosí, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 10, month: 8, year: 1974, tag: 'cumpleaños' }],
    },
    {
      name: 'Magdalena',
      lastName: 'Paco Huanca',
      email: 'magdalena.paco@empresa.bo',
      contacts: [
        { callCode: '+591', number: '64210987', tag: 'móvil' },
        { callCode: '+591', number: '25432109', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Buenos Aires',
          number: '678',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle México',
          number: '901',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 22, month: 7, year: 1985, tag: 'cumpleaños' },
        { day: 22, month: 7, year: 2010, tag: 'día de magdalena' },
      ],
    },
    {
      name: 'Nicolás',
      lastName: 'Ramos Silva',
      email: 'nicolas.ramos@hotmail.com',
      contacts: [
        { callCode: '+591', number: '73210987', tag: 'móvil' },
        { callCode: '+591', number: '67890123', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Barrio Equipetrol',
          number: '234',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 6, month: 12, year: 1983, tag: 'cumpleaños' },
        { day: 6, month: 12, year: 2015, tag: 'día de san nicolás' },
      ],
    },
    {
      name: 'Olga',
      lastName: 'Fernández Castro',
      email: 'olga.fernandez@outlook.com',
      contacts: [{ callCode: '+591', number: '69109876', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Campero',
          number: '567',
          location: 'Sucre, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 11, month: 7, year: 1990, tag: 'cumpleaños' }],
    },
    {
      name: 'Pablo',
      lastName: 'Durán Morales',
      email: 'pablo.duran@gmail.com',
      contacts: [
        { callCode: '+591', number: '76109876', tag: 'móvil' },
        { callCode: '+591', number: '43210987', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Av. Melchor Pérez',
          number: '890',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
        {
          street: 'Zona Sur',
          number: '123',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
      ],
      importantDates: [
        { day: 29, month: 6, year: 1981, tag: 'cumpleaños' },
        { day: 29, month: 6, year: 2008, tag: 'día de san pablo' },
      ],
    },
    {
      name: 'Rocío',
      lastName: 'Herrera Vega',
      email: 'rocio.herrera@empresa.com',
      contacts: [
        { callCode: '+591', number: '65109876', tag: 'móvil' },
        { callCode: '+591', number: '22109876', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Av. Arce',
          number: '456',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 16, month: 8, year: 1992, tag: 'cumpleaños' },
        { day: 16, month: 8, year: 2020, tag: 'día de rocío' },
      ],
    },
    {
      name: 'Sergio',
      lastName: 'Molina Rojas',
      email: 'sergio.molina@yahoo.com',
      contacts: [{ callCode: '+591', number: '72109876', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Libertad',
          number: '789',
          location: 'Oruro, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 23, month: 9, year: 1979, tag: 'cumpleaños' }],
    },
    {
      name: 'Teresa',
      lastName: 'Villarroel Guzmán',
      email: 'teresa.villarroel@hotmail.com',
      contacts: [
        { callCode: '+591', number: '68109876', tag: 'móvil' },
        { callCode: '+591', number: '24109876', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Simón Bolívar',
          number: '123',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Yanacocha',
          number: '456',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 15, month: 10, year: 1987, tag: 'cumpleaños' },
        { day: 15, month: 10, year: 2014, tag: 'día de santa teresa' },
      ],
    },
    {
      name: 'Ulises',
      lastName: 'Sandoval Choque',
      email: 'ulises.sandoval@gmail.com',
      contacts: [
        { callCode: '+591', number: '77109876', tag: 'móvil' },
        { callCode: '+591', number: '65109876', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Av. Roca y Coronado',
          number: '789',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 20, month: 11, year: 1985, tag: 'cumpleaños' }],
    },
    {
      name: 'Valeria',
      lastName: 'Cruz Mamani',
      email: 'valeria.cruz@outlook.com',
      contacts: [{ callCode: '+591', number: '63109876', tag: 'móvil' }],
      addresses: [
        {
          street: 'Barrio Villa Fátima',
          number: '234',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 14, month: 2, year: 1994, tag: 'cumpleaños' },
        { day: 14, month: 2, year: 2022, tag: 'día de los enamorados' },
      ],
    },
    {
      name: 'William',
      lastName: 'Paredes Inca',
      email: 'william.paredes@empresa.bo',
      contacts: [
        { callCode: '+591', number: '74109876', tag: 'móvil' },
        { callCode: '+591', number: '44109876', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Av. República',
          number: '567',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Jordán',
          number: '890',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 19, month: 3, year: 1982, tag: 'cumpleaños' },
        { day: 19, month: 3, year: 2011, tag: 'día del padre' },
      ],
    },
    {
      name: 'Ximena',
      lastName: 'Aguilar Portillo',
      email: 'ximena.aguilar@hotmail.com',
      contacts: [
        { callCode: '+591', number: '69543210', tag: 'móvil' },
        { callCode: '+591', number: '33109876', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Roca y Coronado',
          number: '123',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 8, month: 12, year: 1990, tag: 'cumpleaños' },
        { day: 8, month: 12, year: 2017, tag: 'inmaculada concepción' },
      ],
    },
    {
      name: 'Yolanda',
      lastName: 'Saavedra Nina',
      email: 'yolanda.saavedra@yahoo.com',
      contacts: [{ callCode: '+591', number: '66543210', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Calama',
          number: '456',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 17, month: 12, year: 1986, tag: 'cumpleaños' }],
    },
    {
      name: 'Zenón',
      lastName: 'Ayala Condori',
      email: 'zenon.ayala@gmail.com',
      contacts: [
        { callCode: '+591', number: '75543210', tag: 'móvil' },
        { callCode: '+591', number: '26543210', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Av. Del Ejercito',
          number: '789',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 12, month: 4, year: 1976, tag: 'cumpleaños' }],
    },
    {
      name: 'Amelia',
      lastName: 'Cordero Salinas',
      email: 'amelia.cordero@empresa.com',
      contacts: [
        { callCode: '+591', number: '62543210', tag: 'móvil' },
        { callCode: '+591', number: '45543210', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Calle Venezuela',
          number: '123',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Av. Pando',
          number: '456',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 5, month: 5, year: 1989, tag: 'cumpleaños' },
        { day: 5, month: 5, year: 2016, tag: 'día de amelia' },
      ],
    },
    {
      name: 'Bernardo',
      lastName: 'Tórrez Huanca',
      email: 'bernardo.torrez@outlook.com',
      contacts: [{ callCode: '+591', number: '71543210', tag: 'móvil' }],
      addresses: [
        {
          street: 'Barrio San Antonio',
          number: '789',
          location: 'Tarija, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 20, month: 8, year: 1978, tag: 'cumpleaños' },
        { day: 20, month: 8, year: 2005, tag: 'día de san bernardo' },
      ],
    },
    {
      name: 'Cecilia',
      lastName: 'Miranda Apaza',
      email: 'cecilia.miranda@hotmail.com',
      contacts: [
        { callCode: '+591', number: '67543210', tag: 'móvil' },
        { callCode: '+591', number: '23543210', tag: 'casa' },
      ],
      addresses: [
        {
          street: 'Calle Genaro Sanjinés',
          number: '234',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 22, month: 11, year: 1993, tag: 'cumpleaños' },
        { day: 22, month: 11, year: 2019, tag: 'día de santa cecilia' },
      ],
    },
    {
      name: 'Damián',
      lastName: 'Colque Quispe',
      email: 'damian.colque@gmail.com',
      contacts: [
        { callCode: '+591', number: '78543210', tag: 'móvil' },
        { callCode: '+591', number: '64543210', tag: 'trabajo' },
      ],
      addresses: [
        {
          street: 'Av. Blanco Galindo Km 4',
          number: '567',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 27, month: 9, year: 1984, tag: 'cumpleaños' },
        { day: 27, month: 9, year: 2012, tag: 'día de san damián' },
      ],
    },
    {
      name: 'Estela',
      lastName: 'Marca Choque',
      email: 'estela.marca@yahoo.com',
      contacts: [{ callCode: '+591', number: '64543210', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Ingavi',
          number: '890',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [{ day: 18, month: 8, year: 1991, tag: 'cumpleaños' }],
    },
    {
      name: 'Fabricio',
      lastName: 'Delgado Vargas',
      email: 'fabricio.delgado@empresa.bo',
      contacts: [
        { callCode: '+591', number: '73543210', tag: 'móvil' },
        { callCode: '+591', number: '35543210', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Barrio Urubó',
          number: '123',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
        {
          street: 'Av. San Martín',
          number: '456',
          location: 'Santa Cruz, Bolivia',
          tag: 'trabajo',
        },
      ],
      importantDates: [
        { day: 11, month: 11, year: 1988, tag: 'cumpleaños' },
        { day: 11, month: 11, year: 2015, tag: 'día de san martín' },
      ],
    },
    {
      name: 'Adriana',
      lastName: 'Bellido Campos',
      email: 'adriana.bellido@medico.com',
      contacts: [
        { callCode: '+591', number: '60123456', tag: 'móvil' },
        { callCode: '+591', number: '42123456', tag: 'consultorio' },
      ],
      addresses: [
        {
          street: 'Calle Estudiantes',
          number: '159',
          location: 'Cochabamba, Bolivia',
          tag: 'consultorio',
        },
        {
          street: 'Av. Circunvalación Norte',
          number: '2847',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 26, month: 6, year: 1990, tag: 'cumpleaños' },
        { day: 15, month: 8, year: 2018, tag: 'graduación medicina' },
      ],
    },
    {
      name: 'Bolivar',
      lastName: 'Quisbert Alanoca',
      email: 'bolivar.quisbert@construccion.bo',
      contacts: [
        { callCode: '+591', number: '79456123', tag: 'móvil' },
        { callCode: '+591', number: '22456123', tag: 'obra' },
      ],
      addresses: [
        {
          street: 'Zona Villa El Carmen',
          number: '2456',
          location: 'El Alto, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 6, month: 8, year: 1975, tag: 'cumpleaños' },
        { day: 6, month: 8, year: 1825, tag: 'independencia de bolivia' },
      ],
    },
    {
      name: 'Claudia',
      lastName: 'Zenteno Flores',
      email: 'claudia.zenteno@universidad.edu.bo',
      contacts: [
        { callCode: '+591', number: '69789456', tag: 'móvil' },
        { callCode: '+591', number: '46789456', tag: 'universidad' },
      ],
      addresses: [
        {
          street: 'Campus Universitario',
          number: 'Bloque C',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Barrio Sarco',
          number: '1847',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 12, month: 10, year: 1985, tag: 'cumpleaños' },
        { day: 12, month: 10, year: 2010, tag: 'día del maestro' },
      ],
    },
    {
      name: 'Demetrio',
      lastName: 'Arce Velasco',
      email: 'demetrio.arce@agricultor.com',
      contacts: [{ callCode: '+591', number: '75123789', tag: 'móvil' }],
      addresses: [
        {
          street: 'Comunidad Achocalla',
          number: 'Parcela 15',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 1, month: 5, year: 1970, tag: 'cumpleaños' },
        { day: 1, month: 5, year: 2000, tag: 'día del trabajador' },
      ],
    },
    {
      name: 'Erlinda',
      lastName: 'Calle Huanaco',
      email: 'erlinda.calle@tienda.bo',
      contacts: [
        { callCode: '+591', number: '68456789', tag: 'móvil' },
        { callCode: '+591', number: '22456789', tag: 'tienda' },
      ],
      addresses: [
        {
          street: 'Mercado Rodríguez',
          number: 'Puesto 47',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Tumusla',
          number: '456',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 24, month: 6, year: 1982, tag: 'cumpleaños' },
        { day: 24, month: 6, year: 2005, tag: 'día de san juan' },
      ],
    },
    {
      name: 'Fidel',
      lastName: 'Mamani Chura',
      email: 'fidel.mamani@transporte.com',
      contacts: [
        { callCode: '+591', number: '77789123', tag: 'móvil' },
        { callCode: '+591', number: '70123789', tag: 'empresa' },
      ],
      addresses: [
        {
          street: 'Terminal de Buses',
          number: 'Oficina 8',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Av. Tejada Sorzano',
          number: '2356',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 13, month: 5, year: 1977, tag: 'cumpleaños' },
        { day: 1, month: 8, year: 2003, tag: 'aniversario empresa' },
      ],
    },
    {
      name: 'Gracia',
      lastName: 'Rodríguez Poma',
      email: 'gracia.rodriguez@enfermera.bo',
      contacts: [
        { callCode: '+591', number: '66123456', tag: 'móvil' },
        { callCode: '+591', number: '44123456', tag: 'hospital' },
      ],
      addresses: [
        {
          street: 'Hospital Viedma',
          number: 'Piso 3',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Barrio Temporal',
          number: '1567',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 8, month: 5, year: 1988, tag: 'cumpleaños' },
        { day: 12, month: 5, year: 2015, tag: 'día de la enfermera' },
      ],
    },
    {
      name: 'Hipólito',
      lastName: 'Vargas Chuquimia',
      email: 'hipolito.vargas@minero.bo',
      contacts: [{ callCode: '+591', number: '72456789', tag: 'móvil' }],
      addresses: [
        {
          street: 'Cerro Rico Sector B',
          number: '789',
          location: 'Potosí, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 13, month: 8, year: 1973, tag: 'cumpleaños' },
        { day: 13, month: 8, year: 2000, tag: 'día del minero' },
      ],
    },
    {
      name: 'Irma',
      lastName: 'Calcina Quispe',
      email: 'irma.calcina@secretaria.com',
      contacts: [
        { callCode: '+591', number: '65789123', tag: 'móvil' },
        { callCode: '+591', number: '25789123', tag: 'oficina' },
      ],
      addresses: [
        {
          street: 'Edificio Multicine',
          number: 'Piso 12',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Final Landaeta',
          number: '2134',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 30, month: 9, year: 1992, tag: 'cumpleaños' },
        { day: 30, month: 9, year: 2018, tag: 'día de la secretaria' },
      ],
    },
    {
      name: 'Jacinto',
      lastName: 'Mendoza Apaza',
      email: 'jacinto.mendoza@veterinario.bo',
      contacts: [
        { callCode: '+591', number: '74789123', tag: 'móvil' },
        { callCode: '+591', number: '33789123', tag: 'veterinaria' },
      ],
      addresses: [
        {
          street: 'Av. Doble Vía La Guardia',
          number: 'Km 8',
          location: 'Santa Cruz, Bolivia',
          tag: 'clínica',
        },
        {
          street: 'Barrio Plan 3000',
          number: '456',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 16, month: 8, year: 1986, tag: 'cumpleaños' },
        { day: 4, month: 10, year: 2012, tag: 'día mundial de los animales' },
      ],
    },
    {
      name: 'Katia',
      lastName: 'Solares Mamani',
      email: 'katia.solares@abogada.bo',
      contacts: [
        { callCode: '+591', number: '61456789', tag: 'móvil' },
        { callCode: '+591', number: '46456789', tag: 'estudio' },
      ],
      addresses: [
        {
          street: 'Calle Hamiraya',
          number: '234',
          location: 'Cochabamba, Bolivia',
          tag: 'estudio',
        },
        {
          street: 'Av. Villazón',
          number: '1678',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 3, month: 7, year: 1991, tag: 'cumpleaños' },
        { day: 3, month: 7, year: 2018, tag: 'graduación derecho' },
      ],
    },
    {
      name: 'Leopoldo',
      lastName: 'Choque Condori',
      email: 'leopoldo.choque@carpintero.com',
      contacts: [{ callCode: '+591', number: '78123456', tag: 'móvil' }],
      addresses: [
        {
          street: 'Av. 6 de Marzo',
          number: '567',
          location: 'El Alto, Bolivia',
          tag: 'taller',
        },
        {
          street: 'Villa Esperanza',
          number: '890',
          location: 'El Alto, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 15, month: 11, year: 1974, tag: 'cumpleaños' },
        { day: 19, month: 3, year: 2008, tag: 'día del padre' },
      ],
    },
    {
      name: 'Marlene',
      lastName: 'Zenteno Miranda',
      email: 'marlene.zenteno@contadora.bo',
      contacts: [
        { callCode: '+591', number: '67123456', tag: 'móvil' },
        { callCode: '+591', number: '27123456', tag: 'consultorio' },
      ],
      addresses: [
        {
          street: 'Calle Cochabamba',
          number: '123',
          location: 'La Paz, Bolivia',
          tag: 'consultorio',
        },
        {
          street: 'Av. Litoral',
          number: '2456',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 25, month: 5, year: 1989, tag: 'cumpleaños' },
        { day: 13, month: 7, year: 2015, tag: 'día del contador' },
      ],
    },
    {
      name: 'Néstor',
      lastName: 'Peña Villarroel',
      email: 'nestor.pena@electricista.com',
      contacts: [
        { callCode: '+591', number: '76456789', tag: 'móvil' },
        { callCode: '+591', number: '62456789', tag: 'emergencias' },
      ],
      addresses: [
        {
          street: 'Av. Petrolera Norte',
          number: 'Km 3',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 21, month: 6, year: 1981, tag: 'cumpleaños' },
        { day: 21, month: 6, year: 2021, tag: 'año nuevo aymara' },
      ],
    },
    {
      name: 'Orfelina',
      lastName: 'Huanca Mamani',
      email: 'orfelina.huanca@cocina.bo',
      contacts: [{ callCode: '+591', number: '64789123', tag: 'móvil' }],
      addresses: [
        {
          street: 'Mercado Central',
          number: 'Puesto 23',
          location: 'Sucre, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Barrio San Roque',
          number: '345',
          location: 'Sucre, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 7, month: 4, year: 1976, tag: 'cumpleaños' },
        { day: 7, month: 4, year: 2010, tag: 'día mundial de la salud' },
      ],
    },
    {
      name: 'Primitivo',
      lastName: 'Arias Torrez',
      email: 'primitivo.arias@ganadero.bo',
      contacts: [
        { callCode: '+591', number: '73789123', tag: 'móvil' },
        { callCode: '+591', number: '39789123', tag: 'estancia' },
      ],
      addresses: [
        {
          street: 'Estancia San Miguel',
          number: 'Km 25',
          location: 'Beni, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Barrio El Trompillo',
          number: '678',
          location: 'Trinidad, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 29, month: 9, year: 1968, tag: 'cumpleaños' },
        { day: 29, month: 9, year: 2015, tag: 'día de san miguel' },
      ],
    },
    {
      name: 'Quintina',
      lastName: 'Flores Condori',
      email: 'quintina.flores@textil.com',
      contacts: [
        { callCode: '+591', number: '62789123', tag: 'móvil' },
        { callCode: '+591', number: '42789123', tag: 'fábrica' },
      ],
      addresses: [
        {
          street: 'Zona Industrial',
          number: 'Manzano 8',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Villa San Miguel',
          number: '1234',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 19, month: 3, year: 1983, tag: 'cumpleaños' },
        { day: 19, month: 3, year: 2019, tag: 'día de san josé' },
      ],
    },
    {
      name: 'Rufino',
      lastName: 'Cáceres Quisbert',
      email: 'rufino.caceres@zapatero.bo',
      contacts: [{ callCode: '+591', number: '71789123', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Max Paredes',
          number: '789',
          location: 'La Paz, Bolivia',
          tag: 'taller',
        },
        {
          street: 'Villa Copacabana',
          number: '2345',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 11, month: 8, year: 1979, tag: 'cumpleaños' },
        { day: 11, month: 8, year: 2007, tag: 'día del zapatero' },
      ],
    },
    {
      name: 'Sabina',
      lastName: 'Gutiérrez Alanoca',
      email: 'sabina.gutierrez@farmacia.bo',
      contacts: [
        { callCode: '+591', number: '68789123', tag: 'móvil' },
        { callCode: '+591', number: '28789123', tag: 'farmacia' },
      ],
      addresses: [
        {
          street: 'Av. Heroínas',
          number: '456',
          location: 'Cochabamba, Bolivia',
          tag: 'farmacia',
        },
        {
          street: 'Barrio Mayorazgo',
          number: '1789',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 27, month: 10, year: 1994, tag: 'cumpleaños' },
        { day: 27, month: 10, year: 2020, tag: 'día del farmacéutico' },
      ],
    },
    {
      name: 'Teófilo',
      lastName: 'Miranda Churata',
      email: 'teofilo.miranda@chofer.com',
      contacts: [
        { callCode: '+591', number: '77789123', tag: 'móvil' },
        { callCode: '+591', number: '37789123', tag: 'radio taxi' },
      ],
      addresses: [
        {
          street: 'Parada Villa Fátima',
          number: 'Radio 15',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Illampu',
          number: '567',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 25, month: 1, year: 1980, tag: 'cumpleaños' },
        { day: 25, month: 1, year: 2009, tag: 'conversión san pablo' },
      ],
    },
    {
      name: 'Ubaldina',
      lastName: 'Condori Vásquez',
      email: 'ubaldina.condori@limpieza.bo',
      contacts: [{ callCode: '+591', number: '65789123', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Indaburo',
          number: '890',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 16, month: 5, year: 1985, tag: 'cumpleaños' },
        { day: 16, month: 5, year: 2012, tag: 'día de san ubaldo' },
      ],
    },
    {
      name: 'Victoriano',
      lastName: 'Mamani Choque',
      email: 'victoriano.mamani@soldador.com',
      contacts: [
        { callCode: '+591', number: '74789123', tag: 'móvil' },
        { callCode: '+591', number: '34789123', tag: 'taller' },
      ],
      addresses: [
        {
          street: 'Zona Industrial Wilstermann',
          number: 'Galpón 12',
          location: 'Cochabamba, Bolivia',
          tag: 'taller',
        },
        {
          street: 'Villa Granado',
          number: '2678',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 23, month: 12, year: 1977, tag: 'cumpleaños' },
        { day: 23, month: 12, year: 2005, tag: 'día de san victoriano' },
      ],
    },
    {
      name: 'Wanda',
      lastName: 'Paredes Huanca',
      email: 'wanda.paredes@peluquera.bo',
      contacts: [{ callCode: '+591', number: '63789123', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Tarija',
          number: '234',
          location: 'La Paz, Bolivia',
          tag: 'salón',
        },
        {
          street: 'Alto Obrajes',
          number: '3456',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 9, month: 7, year: 1996, tag: 'cumpleaños' },
        {
          day: 9,
          month: 7,
          year: 2021,
          tag: 'día de la independencia argentina',
        },
      ],
    },
    {
      name: 'Xenón',
      lastName: 'Callisaya Quispe',
      email: 'xenon.callisaya@mecanico.com',
      contacts: [
        { callCode: '+591', number: '72789123', tag: 'móvil' },
        { callCode: '+591', number: '32789123', tag: 'taller' },
      ],
      addresses: [
        {
          street: 'Av. Circunvalación',
          number: 'Km 7',
          location: 'Santa Cruz, Bolivia',
          tag: 'taller',
        },
        {
          street: 'Barrio Nuevo Palmar',
          number: '567',
          location: 'Santa Cruz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 14, month: 4, year: 1984, tag: 'cumpleaños' },
        { day: 14, month: 4, year: 2010, tag: 'día de las américas' },
      ],
    },
    {
      name: 'Yanet',
      lastName: 'Villca Mamani',
      email: 'yanet.villca@dentista.bo',
      contacts: [
        { callCode: '+591', number: '69789123', tag: 'móvil' },
        { callCode: '+591', number: '29789123', tag: 'consultorio' },
      ],
      addresses: [
        {
          street: 'Calle 25 de Mayo',
          number: '890',
          location: 'Sucre, Bolivia',
          tag: 'consultorio',
        },
        {
          street: 'Barrio Petrolero',
          number: '1456',
          location: 'Sucre, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 3, month: 2, year: 1993, tag: 'cumpleaños' },
        { day: 3, month: 2, year: 2020, tag: 'día mundial contra el cáncer' },
      ],
    },
    {
      name: 'Zacarías',
      lastName: 'Apaza Condori',
      email: 'zacarias.apaza@panadero.bo',
      contacts: [{ callCode: '+591', number: '76789123', tag: 'móvil' }],
      addresses: [
        {
          street: 'Mercado Villa Fátima',
          number: 'Local 56',
          location: 'La Paz, Bolivia',
          tag: 'panadería',
        },
        {
          street: 'Calle Final Manco Kapac',
          number: '4567',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 5, month: 11, year: 1972, tag: 'cumpleaños' },
        { day: 5, month: 11, year: 2008, tag: 'día del panadero' },
      ],
    },
    {
      name: 'América',
      lastName: 'Churata Quispe',
      email: 'america.churata@maestra.edu.bo',
      contacts: [
        { callCode: '+591', number: '65123789', tag: 'móvil' },
        { callCode: '+591', number: '25123789', tag: 'escuela' },
      ],
      addresses: [
        {
          street: 'Unidad Educativa Simón Bolívar',
          number: 'Aula 15',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Almirante Grau',
          number: '2789',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 12, month: 10, year: 1987, tag: 'cumpleaños' },
        { day: 12, month: 10, year: 1492, tag: 'descubrimiento de américa' },
      ],
    },
    {
      name: 'Benedicto',
      lastName: 'Limachi Torrez',
      email: 'benedicto.limachi@jardinero.com',
      contacts: [{ callCode: '+591', number: '74123789', tag: 'móvil' }],
      addresses: [
        {
          street: 'Parque Urbano Central',
          number: 'Sector Norte',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Villa Bush',
          number: '3890',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 11, month: 7, year: 1978, tag: 'cumpleaños' },
        { day: 11, month: 7, year: 2006, tag: 'día de san benedicto' },
      ],
    },
    {
      name: 'Celestina',
      lastName: 'Poma Vásquez',
      email: 'celestina.poma@costurera.bo',
      contacts: [
        { callCode: '+591', number: '63123789', tag: 'móvil' },
        { callCode: '+591', number: '23123789', tag: 'taller' },
      ],
      addresses: [
        {
          street: 'Calle Loayza',
          number: '567',
          location: 'La Paz, Bolivia',
          tag: 'taller',
        },
        {
          street: 'Zona Sur Calacoto',
          number: '4567',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 19, month: 5, year: 1990, tag: 'cumpleaños' },
        { day: 19, month: 5, year: 2017, tag: 'día de santa celestina' },
      ],
    },
    {
      name: 'Doroteo',
      lastName: 'Velasco Mamani',
      email: 'doroteo.velasco@albañil.com',
      contacts: [
        { callCode: '+591', number: '72123789', tag: 'móvil' },
        { callCode: '+591', number: '32123789', tag: 'obra' },
      ],
      addresses: [
        {
          street: 'Villa 1ro de Mayo',
          number: '1234',
          location: 'El Alto, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 6, month: 6, year: 1975, tag: 'cumpleaños' },
        { day: 6, month: 6, year: 2003, tag: 'día de san doroteo' },
      ],
    },
    {
      name: 'Eustaquia',
      lastName: 'Condori Flores',
      email: 'eustaquia.condori@bordadora.bo',
      contacts: [{ callCode: '+591', number: '69123789', tag: 'móvil' }],
      addresses: [
        {
          street: 'Calle Graneros',
          number: '890',
          location: 'La Paz, Bolivia',
          tag: 'taller',
        },
        {
          street: 'Villa Armonía',
          number: '5678',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 20, month: 9, year: 1986, tag: 'cumpleaños' },
        { day: 20, month: 9, year: 2014, tag: 'día de santa eustaquia' },
      ],
    },
    {
      name: 'Florencio',
      lastName: 'Huanca Velasco',
      email: 'florencio.huanca@pescador.bo',
      contacts: [{ callCode: '+591', number: '76123789', tag: 'móvil' }],
      addresses: [
        {
          street: 'Orilla Lago Titicaca',
          number: 'Muelle 12',
          location: 'Copacabana, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Pueblo Copacabana',
          number: '234',
          location: 'Copacabana, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 4, month: 12, year: 1971, tag: 'cumpleaños' },
        { day: 4, month: 12, year: 2009, tag: 'día de san florencio' },
      ],
    },
    {
      name: 'Genara',
      lastName: 'Quisbert Chura',
      email: 'genara.quisbert@artesana.bo',
      contacts: [{ callCode: '+591', number: '65123789', tag: 'móvil' }],
      addresses: [
        {
          street: 'Mercado Witches',
          number: 'Puesto 78',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Calle Santa Cruz',
          number: '6789',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 3, month: 1, year: 1988, tag: 'cumpleaños' },
        { day: 3, month: 1, year: 2016, tag: 'día de santa genara' },
      ],
    },
    {
      name: 'Hilario',
      lastName: 'Torrez Alanoca',
      email: 'hilario.torrez@músico.bo',
      contacts: [
        { callCode: '+591', number: '74123789', tag: 'móvil' },
        { callCode: '+591', number: '34123789', tag: 'estudio' },
      ],
      addresses: [
        {
          street: 'Casa de la Cultura',
          number: 'Sala 5',
          location: 'Cochabamba, Bolivia',
          tag: 'estudio',
        },
        {
          street: 'Villa Coronilla',
          number: '7890',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 13, month: 1, year: 1989, tag: 'cumpleaños' },
        { day: 13, month: 1, year: 2018, tag: 'día de san hilario' },
      ],
    },
    {
      name: 'Ignacia',
      lastName: 'Miranda Quispe',
      email: 'ignacia.miranda@partera.bo',
      contacts: [{ callCode: '+591', number: '63123789', tag: 'móvil' }],
      addresses: [
        {
          street: 'Centro de Salud Temporal',
          number: 'Consulta 3',
          location: 'Cochabamba, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Villa Sebastián Pagador',
          number: '8901',
          location: 'Cochabamba, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 31, month: 7, year: 1983, tag: 'cumpleaños' },
        { day: 31, month: 7, year: 2011, tag: 'día de san ignacio' },
      ],
    },
    {
      name: 'Justiniano',
      lastName: 'Calle Huanca',
      email: 'justiniano.calle@guardia.bo',
      contacts: [
        { callCode: '+591', number: '72123789', tag: 'móvil' },
        { callCode: '+591', number: '32123789', tag: 'cuartel' },
      ],
      addresses: [
        {
          street: 'Regimiento Colorados',
          number: 'Cuartel 7',
          location: 'La Paz, Bolivia',
          tag: 'trabajo',
        },
        {
          street: 'Villa San Antonio',
          number: '9012',
          location: 'La Paz, Bolivia',
          tag: 'casa',
        },
      ],
      importantDates: [
        { day: 1, month: 6, year: 1980, tag: 'cumpleaños' },
        { day: 1, month: 6, year: 2008, tag: 'día de san justiniano' },
      ],
    },
  ],
};
