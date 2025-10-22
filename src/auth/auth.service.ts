import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from 'src/user/entity/user.entity';
import { Repository } from 'typeorm';
import { RegisterRequest } from './dto/register.dto';
import { hash, verify } from 'argon2';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { JwtPayload } from './types/jwt.types';
import { LoginRequest } from './dto/login.dto';
import type { Request, Response } from 'express';
import { isDev } from 'src/utils/is-dev.util';

@Injectable()
export class AuthService {
  private JWT_ACCESS_TOKEN_TTL: string;
  private JWT_REFRESH_TOKEN_TTL: string;
  private COOKIE_DOMAIN: string;

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {
    this.JWT_ACCESS_TOKEN_TTL = this.configService.getOrThrow(
      'JWT_ACCESS_TOKEN_TTL',
    );
    this.JWT_REFRESH_TOKEN_TTL = this.configService.getOrThrow(
      'JWT_REFRESH_TOKEN_TTL',
    );
    this.COOKIE_DOMAIN = this.configService.getOrThrow('COOKIE_DOMAIN');
  }

  async login(res: Response, dto: LoginRequest) {
    const { email, password } = dto;

    const user = await this.userRepository.findOne({
      where: {
        email,
      },
      select: {
        id: true,
        password: true,
      },
    });

    if (!user) {
      throw new NotFoundException('Пользователь не найден');
    }

    const isValidPassword = await verify(user.password, password);

    if (!isValidPassword) {
      throw new NotFoundException('Пароль не верный');
    }

    return this.auth(res, user.id);
  }

  async register(res: Response, dto: RegisterRequest) {
    const { name, email, password } = dto;

    const existUser = await this.userRepository.findOne({
      where: { email },
    });

    if (existUser) {
      throw new ConflictException('Пользователь с такой почтой уже существует');
    }

    const user = this.userRepository.create({
      name,
      email,
      password: await hash(password),
    });

    await this.userRepository.save(user);

    return this.auth(res, user.id);
  }

  logout(res: Response) {
    this.setCookie(res, 'refreshToken', new Date(0));

    return 'Вы вышли из системы';
  }

  async validate(id: string) {
    const user = await this.userRepository.findOne({
      where: {
        id,
      },
    });

    if (!user) {
      throw new NotFoundException('Пользователь не найден');
    }

    return user;
  }

  async refresh(req: Request, res: Response) {
    const refreshToken = req.cookies['refreshToken'] as string;

    if (!refreshToken) {
      throw new UnauthorizedException('Недействительный refresh-токен');
    }

    const payload: JwtPayload = await this.jwtService.verifyAsync(refreshToken);

    if (payload) {
      const user = await this.userRepository.findOne({
        where: {
          id: payload.id,
        },
        select: {
          id: true,
        },
      });

      if (!user) {
        throw new NotFoundException('Пользователь не найден');
      }

      return this.auth(res, user.id);
    }
  }

  private auth(res: Response, id: string) {
    const { accessToken, refreshToken } = this.generateTokens(id);

    this.setCookie(res, refreshToken, new Date(Date.now() + 60 * 60 * 24 * 7));

    return { accessToken };
  }

  private generateTokens(id: string) {
    const payload: JwtPayload = { id };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.JWT_ACCESS_TOKEN_TTL as '2h',
    });
    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: this.JWT_REFRESH_TOKEN_TTL as '7d',
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  private setCookie(res: Response, value: string, expires: Date) {
    res.cookie('refreshToken', value, {
      httpOnly: true,
      domain: this.COOKIE_DOMAIN,
      expires,
      secure: !isDev(this.configService),
      sameSite: isDev(this.configService) ? 'none' : 'lax',
    });
  }
}
