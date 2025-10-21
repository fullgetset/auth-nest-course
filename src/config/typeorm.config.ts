import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export const getTypeOrmConfig = async (
  configService: ConfigService,
  // eslint-disable-next-line @typescript-eslint/require-await
): Promise<TypeOrmModuleOptions> => ({
  type: 'postgres',
  host: configService.getOrThrow('POSTGRES_HOST'),
  port: configService.getOrThrow('POSTGRES_PORT'),
  username: configService.getOrThrow('POSTGRES_USER'),
  password: configService.getOrThrow('POSTGRES_PASSWORD'),
  database: configService.getOrThrow('POSTGRES_DATABASE'),
  autoLoadEntities: true, // автоматически загружать все сущности
  synchronize: true, // автосинхранизация в разработке. Динамическое обновление данных
});
