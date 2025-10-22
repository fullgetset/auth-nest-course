import { DocumentBuilder } from '@nestjs/swagger';

export const getSwaggerConfig = () => {
  return new DocumentBuilder()
    .setTitle('Awesome API')
    .setDescription('Simple REST API built for auth-nest-course')
    .setVersion('1.0.0')
    .addBearerAuth()
    .build();
};
