import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class LoginRequest {
  @IsString({ message: 'Емейл должен быть строкой' })
  @IsNotEmpty({ message: 'Емейл обязателен для заполнения' })
  @IsEmail({}, { message: 'Некорректный формат эл. почты' })
  email: string;

  @IsString({ message: 'Пароль должен быть строкой' })
  @IsNotEmpty({ message: 'Пароль обязателен для заполнения' })
  @MinLength(6, { message: 'Пароль должен содержать не менее 6 символов' })
  @MaxLength(128, { message: 'Пароль не должен превышать 128 символов' })
  password: string;
}
