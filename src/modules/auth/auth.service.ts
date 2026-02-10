import requestIp from 'request-ip';
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
import { SendEmailVerifyDto } from './dto/send-email-verify.dto';
import { Request } from './entities/auth-user.entity';
import { TimeService } from 'src/time/time.service';
import { AuthUserLoginLog } from './entities/auth-user-login-log.entity';
import ENUMS from 'src/enum';
import { I18nContext, I18nService } from 'nestjs-i18n';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { OAuth2Client } from 'google-auth-library';
import { LoginGoogleDto } from './dto/login-google';
import axios from 'axios';

export interface CountryCallingCodeItem {
  country: string; // ISO 3166-1 alpha-2 (e.g. "TW")
  callingCode: string; // e.g. "886"
  name: string; // localized country name
}

@Injectable()
export class AuthService {
  private readonly resend: Resend;
  private googleClient: OAuth2Client;
  private cache = new Map<string, CountryCallingCodeItem[]>();

  constructor(
    @InjectRepository(AuthUser)
    private readonly userRep: Repository<AuthUser>,
    private readonly config: ConfigService,
    private readonly timeSv: TimeService,
    private readonly jwtSv: JwtService,
    private readonly i18n: I18nService,
  ) {
    this.resend = new Resend(this.config.get<string>('RESEND_API_KEY') || '');
    this.googleClient = new OAuth2Client(
      this.config.get<string>('GOOGLE_CLIENT_ID'),
    );
  }

  async register(account: string, password: string, name: string) {
    const exists = await this.userRep.findOne({ where: { account } });
    if (exists) throw new HttpException('帳號已存在', HttpStatus.BAD_REQUEST);

    const hash = await bcrypt.hash(password, 10);

    const user = this.userRep.create({
      account,
      password: hash,
      name,
      tokenVersion: 0,
    });

    const saved = await this.userRep.save(user);

    const token = await this.jwtSv.signAsync({
      sub: saved.id,
      account: saved.account,
      tokenVersion: saved.tokenVersion ?? 0,
    });

    return { token, user: { id: saved.id, name: saved.name } };
  }

  async login(account: string, password: string, req: Request) {
    const user = await this.userRep.findOne({ where: { account } });
    if (!user) throw new UnauthorizedException('帳號或密碼錯誤');

    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('帳號或密碼錯誤');

    const logData = {
      ip: requestIp.getClientIp(req) || '',
      device: (req.headers['user-agent'] as string) || 'unknown',
      lastUse: this.timeSv.nowDate(),
    };

    const { password: _password, ...freshUser } =
      await this.userRep.manager.transaction(async (manager) => {
        /**
         * transaction + manager.getRepository(...) 的特色 / 好處
         *
         * 1) 原子性（Atomic）
         *    - 這一包操作「要嘛全部成功、要嘛全部回滾」
         *    - 例：
         *      - tokenVersion + 1 成功
         *      - 但 insert login log 失敗
         *      => 整包 rollback，tokenVersion 不會被改（避免資料半套）
         *
         * 2) 一致性（Consistent）
         *    - 同一個交易中查到/更新到的資料屬於同一個時間點（同一份一致視圖）
         *    - 不容易出現 race condition（例如同帳號同時兩次登入互踩）
         *
         * 3) 同一個連線 / 同一個 manager
         *    - transaction 裡拿到的 repository 都掛在同一個 EntityManager / connection 上
         *    - 你的更新、查詢、insert 都是在同一條 DB 連線的交易內完成 **/

        const userRepo = manager.getRepository(AuthUser);
        const loginLogRepo = manager.getRepository(AuthUserLoginLog);

        await userRepo.increment({ id: user.id }, 'tokenVersion', 1);

        const freshUser = await userRepo.findOneOrFail({
          where: { id: user.id },
        });

        const lastLogin = await loginLogRepo.findOne({
          where: { userId: user.id, action: 'LOGIN' },
          order: { lastUse: 'DESC' },
        });

        if (lastLogin) {
          await loginLogRepo.update(
            { id: lastLogin.id },
            { action: 'LOGOUT', lastUse: logData.lastUse },
          );
        }

        await loginLogRepo.insert({
          userId: user.id,
          device: logData.device,
          ip: logData.ip,
          lastUse: logData.lastUse,
          action: 'LOGIN',
        });

        return freshUser;
      });

    const token = this.jwtSv.sign({
      sub: freshUser.id,
      account: freshUser.account,
      tokenVersion: freshUser.tokenVersion,
    });

    return { token, user: freshUser };
  }

  async getUserDetail(query, req) {
    const searchLoginLog = (query?.RELATED || []).includes(query.RELATED);

    const user = await this.userRep.findOne({
      where: { account: req.user.account },
      relations: { loginLogs: searchLoginLog },
    });

    if (user && searchLoginLog) {
      const loginLogs = await this.userRep.manager
        .getRepository(AuthUserLoginLog)
        .find({
          where: { userId: user.id },
          order: { lastUse: 'DESC' },
          take: 20,
        });

      return { ...user, loginLogs };
    }

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

  async sendVerifyEmail(dto: SendEmailVerifyDto, req: Request) {
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
      { emailVerifyCode: code },
    );

    if (error) throw new Error(`Resend error: ${error.message}`);
    return data;
  }

  async checkVerifyEmail(dto, req: Request) {
    const user = await this.userRep.findOne({
      where: { account: req.user?.account },
    });

    if (!user?.emailVerifyCode) {
      throw new HttpException(
        { code: 2001, message: this.i18n.t('auth.checkVerifyEmail.2001') },
        HttpStatus.BAD_REQUEST,
      );
    }

    if (dto.code !== user.emailVerifyCode) {
      throw new HttpException(
        { code: 2002, message: this.i18n.t('auth.checkVerifyEmail.2002') },
        HttpStatus.BAD_REQUEST,
      );
    }

    this.userRep.update({ account: req.user?.account }, { email: dto.email });
  }

  async generateGoogleAuth(req: Request) {
    const user = await this.userRep.findOne({
      where: { account: req.user?.account },
    });

    const secret = speakeasy.generateSecret({
      length: 20,
      name: `${process.env.APP_NAME}-${user?.account}`,
    });

    await this.userRep.update(
      { account: user?.account },
      {
        googleAuthSecret: secret.base32,
        googleAuthEnabled: 0,
      },
    );

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      qrCode: qrCodeUrl,
    };
  }

  async verifyGoogleAuth(token: string, secret: string) {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1,
    });
  }

  async enableGoogleAuth(dto, req: Request) {
    const { code } = dto;

    const user = await this.userRep.findOne({
      where: { account: req.user?.account },
    });

    if (!user || !user.googleAuthSecret) {
      throw new HttpException(
        { code: 2001, message: this.i18n.t('auth.enableGoogleAuth.2001') },
        HttpStatus.BAD_REQUEST,
      );
    }

    const isValid = await this.verifyGoogleAuth(code, user.googleAuthSecret);
    if (!isValid) {
      throw new HttpException(
        { code: 2002, message: this.i18n.t('auth.enableGoogleAuth.2002') },
        HttpStatus.BAD_REQUEST,
      );
    }

    return await this.userRep.update(
      { account: user.account },
      { googleAuthEnabled: 1 },
    );
  }

  async editPassword(dto, req: Request) {
    const { password, newPassword, confirmPassword } = dto;

    const user = await this.userRep.findOne({
      where: { account: req.user?.account },
    });

    const isPasswordCorrect = await bcrypt.compare(
      password,
      user?.password || '',
    );

    if (!isPasswordCorrect) {
      throw new HttpException(
        { code: 2002, message: this.i18n.t('auth.editPassword.2002') },
        HttpStatus.BAD_REQUEST,
      );
    }

    if (newPassword !== confirmPassword) {
      throw new HttpException(
        { code: 2002, message: this.i18n.t('auth.editPassword.2002') },
        HttpStatus.BAD_REQUEST,
      );
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    return await this.userRep.update(
      { account: req.user?.account },
      { password: newPasswordHash },
    );
  }

  async getLoginConfig() {
    const google = () => {
      const clientId = this.config.get<string>('GOOGLE_CLIENT_ID') || '';
      const redirectUri = this.config.get<string>('GOOGLE_REDIRECT_URI') || '';
      const stateSecret = this.config.get<string>('JWT_SECRET') || '';

      if (!clientId || !redirectUri || !stateSecret) {
        throw new HttpException(
          { code: 2001, message: this.i18n.t('auth.getLoginConfig.2001') },
          HttpStatus.BAD_REQUEST,
        );
      }

      const base64url = (buf: Buffer) =>
        buf
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/g, '');

      const sha256Base64url = (input: string) => {
        const h = require('crypto').createHash('sha256').update(input).digest();
        return base64url(h);
      };

      const randomBase64url = (bytes = 32) => {
        const b = require('crypto').randomBytes(bytes);
        return base64url(b);
      };

      const codeVerifier = randomBase64url(64);
      const codeChallenge = sha256Base64url(codeVerifier);

      // redirectAfter：只允許站內相對路徑，避免 open redirect
      const redirectAfter = '/';

      const statePayload = {
        v: 1,
        n: randomBase64url(16),
        cv: codeVerifier,
        ra: redirectAfter,
        iat: Date.now(),
      };

      const stateBody = Buffer.from(JSON.stringify(statePayload)).toString(
        'base64url',
      );
      const stateSig = require('crypto')
        .createHmac('sha256', stateSecret)
        .update(stateBody)
        .digest('base64url');
      const state = `${stateBody}.${stateSig}`;

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        access_type: 'offline',
        prompt: 'consent',
      });

      return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    };

    return {
      google: google(),
    };
  }

  async loginGoogle(dto: LoginGoogleDto) {
    const { code, state } = dto;

    const clientId = this.config.get<string>('GOOGLE_CLIENT_ID') || '';
    const clientSecret = this.config.get<string>('GOOGLE_CLIENT_SECRET') || '';
    const redirectUri = this.config.get<string>('GOOGLE_REDIRECT_URI') || '';
    const stateSecret = this.config.get<string>('JWT_SECRET') || '';

    if (!clientId || !clientSecret || !redirectUri || !stateSecret) {
      throw new HttpException(
        { code: 2001, message: this.i18n.t('auth.loginGoogle.2001') },
        HttpStatus.BAD_REQUEST,
      );
    }

    // 驗 state（解析 + 驗簽）
    const [stateBody, stateSig] = String(state || '').split('.');
    if (!stateBody || !stateSig) {
      throw new HttpException(
        { code: 2002, message: this.i18n.t('auth.loginGoogle.2002') },
        HttpStatus.BAD_REQUEST,
      );
    }

    const expectedSig = require('crypto')
      .createHmac('sha256', stateSecret)
      .update(stateBody)
      .digest('base64url');

    if (expectedSig !== stateSig) {
      throw new HttpException(
        { code: 2003, message: this.i18n.t('auth.loginGoogle.2003') },
        HttpStatus.BAD_REQUEST,
      );
    }

    let statePayload: any = null;
    try {
      statePayload = JSON.parse(
        Buffer.from(stateBody, 'base64url').toString('utf8'),
      );
    } catch {
      throw new HttpException(
        { code: 2004, message: this.i18n.t('auth.loginGoogle.2004') },
        HttpStatus.BAD_REQUEST,
      );
    }

    // 可選：state 過期（10 分鐘）
    if (
      !statePayload?.iat ||
      Date.now() - Number(statePayload.iat) > 10 * 60 * 1000
    ) {
      throw new HttpException(
        { code: 2005, message: this.i18n.t('auth.loginGoogle.2005') },
        HttpStatus.BAD_REQUEST,
      );
    }

    const codeVerifier = String(statePayload?.cv || '');
    if (!codeVerifier) {
      throw new HttpException(
        { code: 2006, message: this.i18n.t('auth.loginGoogle.2006') },
        HttpStatus.BAD_REQUEST,
      );
    }

    const body = new URLSearchParams({
      code: String(code || ''),
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      code_verifier: codeVerifier,
    }).toString();

    const tokenRes = await axios.post(
      'https://oauth2.googleapis.com/token',
      body,
      {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        validateStatus: () => true,
      },
    );

    const tokenJson = tokenRes.data;

    if (
      tokenRes.status < 200 ||
      tokenRes.status >= 300 ||
      !tokenJson?.id_token
    ) {
      throw new HttpException(
        {
          code: 2007,
          message:
            tokenJson?.error_description ||
            tokenJson?.error ||
            this.i18n.t('auth.loginGoogle.2007'),
        },
        HttpStatus.BAD_REQUEST,
      );
    }

    const idToken = tokenJson.id_token as string;

    let ticket;
    try {
      ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: clientId,
      });
    } catch {
      throw new HttpException(
        { code: 2008, message: this.i18n.t('auth.loginGoogle.2008') },
        HttpStatus.BAD_REQUEST,
      );
    }

    const payload = ticket.getPayload();
    if (!payload?.sub) {
      throw new HttpException(
        { code: 2009, message: this.i18n.t('auth.loginGoogle.2009') },
        HttpStatus.BAD_REQUEST,
      );
    }

    const email = payload.email || '';
    const name = payload.name || '';
    const account = `google_${payload.sub}`;

    let user = email
      ? await this.userRep.findOne({ where: { account } })
      : null;

    if (!user) {
      user = this.userRep.create({
        account,
        email,
        password: '',
        name: name || '',
        tokenVersion: 0,
      });

      user = await this.userRep.save(user);
    }

    const token = this.jwtSv.sign({
      sub: user.id,
      account: user.account,
      tokenVersion: user.tokenVersion ? user.tokenVersion + 1 : 0,
    });

    console.log(ticket, 'ticket');
    console.log(tokenJson, 'tokenJson');
    console.log(payload, 'payload');

    return {
      token,
      user,
      google: { ...tokenJson, ...payload },
    };
  }
}
