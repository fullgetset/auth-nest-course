import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser());

  app.useGlobalPipes(new ValidationPipe());

  const config = new DocumentBuilder()
    .setTitle('Nest js Course')
    .setDescription('API documentation for nest course')
    .setVersion('1.0.0')
    .setContact(
      'Yury Zaikou',
      'https://www.linkedin.com/in/yuri-zaikov/',
      'ye.zaikou@vebtech.by',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('/swagger', app, document);

  await app.listen(process.env.PORT ?? 3000);
}
void bootstrap();
