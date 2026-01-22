import {
  Injectable,
  UnauthorizedException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { AuthUser } from './entities/auth-user.entity';
import {
  parsePhoneNumberFromString,
  AsYouType,
  getCountries,
  getCountryCallingCode,
  type CountryCode,
} from 'libphonenumber-js';

export interface CountryCallingCodeItem {
  country: string; // ISO 3166-1 alpha-2 (e.g. "TW")
  callingCode: string; // e.g. "886"
  name: string; // localized country name
}

@Injectable()
export class AuthService {
  private cache = new Map<string, CountryCallingCodeItem[]>();

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
      throw new HttpException('帳號已存在', HttpStatus.BAD_REQUEST);
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
    if (!user) throw new UnauthorizedException('帳號或密碼錯誤');
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('帳號或密碼錯誤');
    const { password: userPassword, ...payload } = user;
    const token = this.jwtService.sign(payload);
    return { token, ...payload };
  }

  async getUserDetail(req) {
    const user = await this.userRepo.findOne({
      where: { account: req.user.account },
    });

    return user;
  }

  getCountryCodes(req): CountryCallingCodeItem[] {
    const cookies = req.cookies;
    const lang = cookies.i18n_redirected || 'zh-TW';

    const cacheKey = lang;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    let displayNames: Intl.DisplayNames | null = null;

    try {
      displayNames = new Intl.DisplayNames([lang], { type: 'region' });
    } catch {
      try {
        displayNames = new Intl.DisplayNames(['en'], { type: 'region' });
      } catch {
        displayNames = null;
      }
    }

    const list = getCountries()
      .map((country) => {
        const callingCode = String(getCountryCallingCode(country));
        const name = displayNames?.of(country) || country;
        return { country, callingCode, name };
      })
      .sort((a, b) => a.name.localeCompare(b.name, lang));

    this.cache.set(cacheKey, list);
    return list;
  }
}
