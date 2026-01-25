import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Repository } from 'typeorm';
import { AuthUser } from '../entities/auth-user.entity';

type JwtPayload = {
  sub: number;
  account: string;
  tokenVersion: number;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly config: ConfigService,
    @InjectRepository(AuthUser)
    private readonly userRep: Repository<AuthUser>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('JWT_SECRET') || 'c9-secret',
      ignoreExpiration: false,
    });
  }

  async validate(payload: JwtPayload) {
    // 查 DB 取 tokenVersion（只選必要欄位）
    const user = await this.userRep.findOne({
      where: { id: payload.sub },
      select: ['id', 'account', 'tokenVersion'],
    });

    if (!user) throw new UnauthorizedException('無效的 token');

    // 不一致代表舊 token → 立刻踢出（401）
    if (user.tokenVersion !== payload.tokenVersion) {
      throw new UnauthorizedException('token 已失效，請重新登入');
    }

    // 這個回傳值會掛在 req.user
    return { id: user.id, account: user.account };
  }
}
