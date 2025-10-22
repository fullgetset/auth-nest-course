import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { UserEntity } from 'src/user/entity/user.entity';

export const Authorized = createParamDecorator(
  (data: keyof UserEntity, context: ExecutionContext) => {
    // eslint-disable-next-line
    const request = context.switchToHttp().getRequest() as Request;

    const user = request.user;

    // eslint-disable-next-line
    return data ? user![data] : user;
  },
);
