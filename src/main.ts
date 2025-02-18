import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as cookieParser from 'cookie-parser';
import * as express from 'express';
import { join } from 'path';
import * as path from 'path'
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const viewsPath = path.join(__dirname, '../src/views');
  app.enableCors();
  app.useGlobalFilters(new AllExceptionsFilter()); // Enable Centralized Error Handling

  app.use(express.static(join(__dirname, '..', 'public')));
  app.setBaseViewsDir(viewsPath);
  app.setViewEngine('ejs');
  app.use(cookieParser());

  // Swagger Configuration
  const config = new DocumentBuilder()
    .setTitle('User Management API') // API Title
    .setDescription('API documentation for user management') // API Description
    .setVersion('1.0') // Version
    .addBearerAuth() // Add Authorization Support (JWT)
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('apis', app, document); 
  
  await app.listen(3000);
}
bootstrap();
