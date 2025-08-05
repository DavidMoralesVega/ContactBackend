import { existsSync } from 'fs';
import { join } from 'path';

import { Injectable, BadRequestException } from '@nestjs/common';

@Injectable()
export class FilesService {
  getStaticPeopleImage(imageName: string) {
    const path = join(__dirname, '../../static/people', imageName);

    if (!existsSync(path))
      throw new BadRequestException(
        `No people photo found with image ${imageName}`,
      );

    return path;
  }
}
