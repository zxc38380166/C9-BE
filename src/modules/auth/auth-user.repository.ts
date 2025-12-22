import { Injectable } from '@nestjs/common';

export interface AuthUser {
  id: number;
  account: string;
  password: string;
}

@Injectable()
export class AuthUserRepository {
  // ❗示範用，之後可換 MySQL / TypeORM
  private users: AuthUser[] = [];

  async findByAccount(account: string) {
    return this.users.find((u) => u.account === account);
  }

  async create(user: AuthUser) {
    this.users.push(user);
    return user;
  }
}
