import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { AuthUser } from './entities/auth-user.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(AuthUser)
    private readonly userRepo: Repository<AuthUser>,
    private readonly jwtService: JwtService,
  ) {}

  /* 註冊 */
  async register(account: string, password: string, name: string) {
    // 1️⃣ 檢查帳號是否存在
    const exists = await this.userRepo.findOne({ where: { account } });
    if (exists) {
      throw new BadRequestException('帳號已存在');
    }

    // 2️⃣ 密碼加密
    const hash = await bcrypt.hash(password, 10);

    // 3️⃣ 建立使用者
    const user = this.userRepo.create({
      account,
      password: hash,
      name,
    });

    await this.userRepo.save(user);

    // 4️⃣ 簽發 JWT
    const payload = {
      sub: user.id,
      account: user.account,
    };

    const token = await this.jwtService.signAsync(payload);

    // 5️⃣ 回傳（對齊前端 useHttp after middleware）
    return {
      token,
      user: {
        id: user.id,
        name: user.name,
      },
    };
  }

  /* 登入 */
  async login(account: string, password: string) {
    const user = await this.userRepo.findOne({ where: { account } });
    if (!user) {
      throw new UnauthorizedException('帳號或密碼錯誤');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new UnauthorizedException('帳號或密碼錯誤');
    }

    const payload = {
      sub: user.id,
      account: user.account,
    };

    const token = this.jwtService.sign(payload);

    return {
      token,
      user: {
        id: user.id,
        name: user.name,
      },
    };
  }
}
