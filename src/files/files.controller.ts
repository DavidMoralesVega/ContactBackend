import {
  Controller,
  Get,
  Post,
  Param,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  Res,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiConsumes,
  ApiParam,
  ApiBody,
} from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';

import { diskStorage } from 'multer';
import { FilesService } from './files.service';
import type { Response } from 'express';

import { fileFilter, fileNamer } from './helpers';

@ApiTags('📁 File Management - Images & Photos')
@Controller('files')
export class FilesController {
  constructor(
    private readonly filesService: FilesService,
    private readonly configService: ConfigService,
  ) {}

  @Get('people/:imageName')
  @ApiOperation({
    summary: '👤 Get people photo',
    description:
      'Retrieves a contact photo by filename. Returns the actual image file for display in contact profiles.',
  })
  @ApiParam({
    name: 'imageName',
    description: 'Photo filename with extension',
    example: 'uuid-filename.jpg',
  })
  @ApiResponse({
    status: 200,
    description: '✅ Photo file returned successfully',
    content: {
      'image/jpeg': { schema: { type: 'string', format: 'binary' } },
      'image/png': { schema: { type: 'string', format: 'binary' } },
      'image/gif': { schema: { type: 'string', format: 'binary' } },
    },
  })
  @ApiResponse({
    status: 400,
    description: '❌ Photo not found',
    schema: {
      example: {
        statusCode: 400,
        message: 'No people photo found with image filename.jpg',
        error: 'Bad Request',
      },
    },
  })
  findPeopleImage(@Res() res: Response, @Param('imageName') imageName: string) {
    const path = this.filesService.getStaticPeopleImage(imageName);
    res.sendFile(path);
  }

  @Post('people')
  @ApiOperation({
    summary: '📷 Upload contact photo',
    description:
      'Uploads a photo for a contact profile. Accepts JPG, JPEG, PNG, and GIF formats. Use the returned URL in the "photo" field when creating or updating contacts.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Photo file to upload for contact',
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
          description:
            'Photo file (JPG, JPEG, PNG, GIF) - recommended square format for contact photos',
        },
      },
    },
  })
  @ApiResponse({
    status: 201,
    description: '✅ Photo uploaded successfully',
    schema: {
      example: {
        secureUrl: 'http://localhost:3000/api/files/people/uuid-filename.jpg',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: '❌ Bad request - Invalid file or file type not supported',
    schema: {
      example: {
        statusCode: 400,
        message: 'Make sure that the file is an image',
        error: 'Bad Request',
      },
    },
  })
  @UseInterceptors(
    FileInterceptor('file', {
      fileFilter: fileFilter,
      storage: diskStorage({
        destination: './static/people',
        filename: fileNamer,
      }),
    }),
  )
  uploadPeopleImage(@UploadedFile() file: Express.Multer.File) {
    if (!file) {
      throw new BadRequestException('Make sure that the file is an image');
    }

    const secureUrl = `${this.configService.get('HOST_API')}/files/people/${file.filename}`;
    return { secureUrl };
  }
}
