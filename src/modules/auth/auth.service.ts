import {
  Injectable,
  UnauthorizedException,
  HttpException,
  HttpStatus,
  ConflictException,
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
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';
import { randomInt } from 'crypto';
import { SendTestDto } from './dto/send-email-vertify.dto';
import { Request } from './entities/auth-user.entity';

export interface CountryCallingCodeItem {
  country: string; // ISO 3166-1 alpha-2 (e.g. "TW")
  callingCode: string; // e.g. "886"
  name: string; // localized country name
}

@Injectable()
export class AuthService {
  private readonly resend: Resend;
  private cache = new Map<string, CountryCallingCodeItem[]>();

  constructor(
    @InjectRepository(AuthUser)
    private readonly userRep: Repository<AuthUser>,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
  ) {
    const apiKey = this.config.get<string>('RESEND_API_KEY') || '';
    console.log(apiKey, 'apiKey');

    this.resend = new Resend(apiKey);
  }

  async register(account: string, password: string, name: string) {
    // 1️⃣ 檢查帳號是否存在
    const exists = await this.userRep.findOne({ where: { account } });
    if (exists) {
      throw new HttpException('帳號已存在', HttpStatus.BAD_REQUEST);
    }

    // 2️⃣ 密碼加密
    const hash = await bcrypt.hash(password, 10);

    // 3️⃣ 建立使用者
    const user = this.userRep.create({
      account,
      password: hash,
      name,
    });

    await this.userRep.save(user);

    // 4️⃣ 簽發 JWT
    const payload = { sub: user.id, account: user.account };
    const token = await this.jwtService.signAsync(payload);

    // 5️⃣ 回傳（對齊前端 useHttp after middleware）
    return {
      token,
      user: { id: user.id, name: user.name },
    };
  }

  async login(account: string, password: string) {
    const user = await this.userRep.findOne({ where: { account } });
    if (!user) throw new UnauthorizedException('帳號或密碼錯誤');
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('帳號或密碼錯誤');
    const { password: userPassword, ...payload } = user;
    const token = this.jwtService.sign(payload);
    return { token, ...payload };
  }

  async getUserDetail(req) {
    const user = await this.userRep.findOne({
      where: { account: req.user.account },
    });

    return user;
  }

  async getCountryCodes(req): Promise<CountryCallingCodeItem[]> {
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

  async created6DigitCode(): Promise<string> {
    const blacklist = new Set(['000000']); // 黑名單

    const isAllSame = (s: string) => s.split('').every((c) => c === s[0]);

    const isSequential = (s: string) => {
      let inc = true,
        dec = true;
      for (let i = 1; i < s.length; i++) {
        const prev = s.charCodeAt(i - 1) - 48;
        const cur = s.charCodeAt(i) - 48;
        if (cur !== prev + 1) inc = false;
        if (cur !== prev - 1) dec = false;
        if (!inc && !dec) return false;
      }
      return inc || dec;
    };

    for (let i = 0; i < 30; i++) {
      const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
      if (blacklist.has(code)) continue;
      if (isAllSame(code)) continue;
      if (isSequential(code)) continue;
      return code;
    }

    // fallback（仍避開黑名單）
    for (;;) {
      const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
      if (!blacklist.has(code)) return code;
    }
  }

  async sendVertifyEmail(dto: SendTestDto, req: Request) {
    const { email, subject = 'C9邀請您驗證信箱' } = dto;

    const existed = await this.userRep.findOne({
      where: { email },
      select: ['id'],
    });

    if (existed) throw new ConflictException('此信箱已被其他帳號使用');

    const code = await this.created6DigitCode();
    const from = this.config.get('RESEND_FROM') || '';

    const { data, error } = await this.resend.emails.send({
      from,
      to: email,
      subject,
      html: `
        <div style="font-family: Arial; line-height: 1.6">
          <h3>您的信箱驗證碼為: </h3>
          <p>${code}</p>
          <p style="color:#666;font-size:12px">Sent at: ${new Date().toISOString()}</p>
        </div>
      `,
    });

    this.userRep.update(
      { account: req.user?.account },
      { emailVertifyCode: code },
    );

    if (error) throw new Error(`Resend error: ${error.message}`);
    return data;
  }

  async checkVertifyEmail(dto, req: Request) {
    const user = await this.userRep.findOne({
      where: { account: req.user?.account },
    });

    if (!user?.emailVertifyCode) {
      throw new HttpException('查無驗證資訊', HttpStatus.BAD_REQUEST);
    }

    if (dto.code !== user.emailVertifyCode) {
      throw new HttpException('驗證碼錯誤', HttpStatus.BAD_REQUEST);
    }

    this.userRep.update({ account: req.user?.account }, { email: dto.email });
  }
}
